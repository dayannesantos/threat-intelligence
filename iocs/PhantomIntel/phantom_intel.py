import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO

import pandas as pd
import requests
import streamlit as st
from openai import OpenAI

from phantomintel.config import get_data_dir
from phantomintel.risk import risk_to_score
from phantomintel.sources import (
    fetch_openphish_feed,
    query_abuseipdb,
    query_censys,
    query_openphish_url,
    query_otx,
    query_shodan,
)
from phantomintel.storage import (
    get_cached_result,
    load_intel_data,
    load_cache,
    load_saved_keys,
    now_str,
    save_cache,
    save_intel_data,
    save_keys,
    set_cached_result,
    prune_expired_cache,
    upsert_intel_entry,
)
from phantomintel.validators import normalize_ioc_value, validate_ioc

try:
    import keyring  # noqa: F401
except Exception:
    keyring = None


def bootstrap_session():
    saved_keys = load_saved_keys()
    for key_name, key_value in saved_keys.items():
        st.session_state[key_name] = key_value

    if "intel_data" not in st.session_state:
        st.session_state.intel_data = load_intel_data()
    if "ioc_cache" not in st.session_state:
        st.session_state.ioc_cache = load_cache()
    if "last_batch_results" not in st.session_state:
        st.session_state.last_batch_results = []


def render_sidebar():
    with st.sidebar:
        st.header("Suas API Keys")

        xai_key = st.text_input(
            "xAI Grok API Key",
            type="password",
            value=st.session_state.get("xai_key", ""),
            key="xai_key_input",
        )
        otx_key = st.text_input(
            "AlienVault OTX API Key (opcional)",
            type="password",
            value=st.session_state.get("otx_key", ""),
            key="otx_key_input",
        )
        abuse_key = st.text_input(
            "AbuseIPDB API Key (opcional)",
            type="password",
            value=st.session_state.get("abuse_key", ""),
            key="abuse_key_input",
        )
        shodan_key = st.text_input(
            "Shodan API Key (opcional)",
            type="password",
            value=st.session_state.get("shodan_key", ""),
            key="shodan_key_input",
        )
        censys_token = st.text_input(
            "Censys Personal Access Token",
            type="password",
            value=st.session_state.get("censys_token", ""),
            key="censys_token_input",
            help="Token da pagina Personal Access Tokens",
        )

        if st.button("Salvar Keys"):
            keys = {
                "xai_key": xai_key,
                "otx_key": otx_key,
                "abuse_key": abuse_key,
                "shodan_key": shodan_key,
                "censys_token": censys_token,
            }
            for key_name, key_value in keys.items():
                st.session_state[key_name] = key_value

            errors = save_keys(keys)
            if errors:
                st.error("Falha ao salvar algumas chaves: " + " | ".join(errors))
            else:
                st.success("Keys salvas com sucesso.")
            st.rerun()

        st.divider()
        st.caption(f"Dados locais em: {get_data_dir()}")
        if not keyring:
            st.warning("Keyring nao disponivel: armazenamento local em arquivo.")

        st.divider()
        cache_ttl_minutes = st.number_input(
            "TTL do cache (minutos)",
            min_value=1,
            max_value=1440,
            value=30,
            step=1,
        )
        st.caption("Consultas repetidas no periodo usam cache local.")
        removed = prune_expired_cache(st.session_state.ioc_cache, int(cache_ttl_minutes) * 60)
        if removed > 0:
            save_cache(st.session_state.ioc_cache)
            st.caption(f"Cache limpo automaticamente: {removed} entradas expiradas.")
        st.divider()
        batch_workers = st.number_input(
            "Paralelismo do lote (workers)",
            min_value=1,
            max_value=10,
            value=4,
            step=1,
        )
        st.caption("Aumente para acelerar lotes grandes.")
        st.divider()
        model = st.selectbox(
            "Modelo Grok",
            ["grok-4-fast-reasoning", "grok-4-1-fast-reasoning", "grok-4-fast-non-reasoning"],
            index=0,
        )
    return model, int(cache_ttl_minutes) * 60, int(batch_workers)


def append_result_entry(ioc_type, ioc_value, source_result):
    entry = {
        "timestamp": now_str(),
        "type": ioc_type,
        "value": ioc_value,
        "source": source_result["source"],
        "risk": source_result["risk"],
        "risk_score": source_result.get("risk_score", risk_to_score(source_result["risk"])),
        "details": source_result["details"],
    }
    upsert_intel_entry(st.session_state.intel_data, entry)


def run_query_with_cache(cache_store, source_name, ioc_type, ioc_value, ttl_seconds, query_func):
    cached = get_cached_result(cache_store, source_name, ioc_type, ioc_value, ttl_seconds)
    if cached is not None:
        return cached, None, True

    result, err = query_func()
    return result, err, False


def process_single_ioc_stateless(ioc_type, raw_ioc_value, ttl_seconds, keys, cache_snapshot):
    is_valid, validation_error = validate_ioc(ioc_type, raw_ioc_value)
    if not is_valid:
        return None, None, [validation_error], [], []

    ioc_value = normalize_ioc_value(ioc_type, raw_ioc_value)
    results = []
    source_errors = []
    cache_hits = []
    cache_updates = []

    if ioc_type == "URL":
        result, err, from_cache = run_query_with_cache(
            cache_snapshot, "OpenPhish", ioc_type, ioc_value, ttl_seconds, lambda: query_openphish_url(ioc_value)
        )
        if result:
            results.append(result)
            if from_cache:
                cache_hits.append("OpenPhish")
            else:
                cache_updates.append(("OpenPhish", ioc_type, ioc_value, result))
        if err:
            source_errors.append(err)

    if keys.get("otx_key"):
        result, err, from_cache = run_query_with_cache(
            cache_snapshot, "OTX", ioc_type, ioc_value, ttl_seconds, lambda: query_otx(ioc_type, ioc_value, keys["otx_key"])
        )
        if result:
            results.append(result)
            if from_cache:
                cache_hits.append("OTX")
            else:
                cache_updates.append(("OTX", ioc_type, ioc_value, result))
        if err:
            source_errors.append(err)

    if keys.get("abuse_key") and ioc_type == "IP":
        result, err, from_cache = run_query_with_cache(
            cache_snapshot, "AbuseIPDB", ioc_type, ioc_value, ttl_seconds, lambda: query_abuseipdb(ioc_value, keys["abuse_key"])
        )
        if result:
            results.append(result)
            if from_cache:
                cache_hits.append("AbuseIPDB")
            else:
                cache_updates.append(("AbuseIPDB", ioc_type, ioc_value, result))
        if err:
            source_errors.append(err)

    return ioc_type, ioc_value, results, source_errors, cache_hits, cache_updates


def persist_query_outcome(ioc_type, ioc_value, results, cache_updates):
    for source_result in results:
        append_result_entry(ioc_type, ioc_value, source_result)
    for source_name, cache_ioc_type, cache_ioc_value, result in cache_updates:
        set_cached_result(st.session_state.ioc_cache, source_name, cache_ioc_type, cache_ioc_value, result)
    if results:
        save_intel_data(st.session_state.intel_data)
    if cache_updates:
        save_cache(st.session_state.ioc_cache)


def render_dashboard():
    st.header("Dashboard")
    if not st.session_state.intel_data:
        st.info("Nenhum dado ainda. Comece na aba 'Busca IOC'.")
        return

    df = pd.DataFrame(st.session_state.intel_data)
    col1, col2, col3 = st.columns(3)
    col1.metric("IOCs Analisados", len(df))
    col2.metric("Fontes Ativas", len(df["source"].unique()) if not df.empty else 0)
    col3.metric("Ultima Atualizacao", df["timestamp"].max() if not df.empty else "-")

    st.subheader("IOCs por Tipo")
    st.bar_chart(df["type"].value_counts())

    show_cols = ["type", "value", "source", "risk", "risk_score", "details"]
    final_cols = [col for col in show_cols if col in df.columns]
    st.dataframe(df[final_cols], use_container_width=True)


def render_ioc_search(cache_ttl_seconds):
    st.header("Busca Inteligente de IOC")
    ioc_type = st.selectbox("Tipo de IOC", ["IP", "Domain", "URL", "Hash"])
    ioc_value = st.text_input("Valor do IOC (ex: 8.8.8.8 ou malicious.com)")

    if st.button("Buscar em todas as fontes") and ioc_value:
        keys = {
            "otx_key": st.session_state.get("otx_key", ""),
            "abuse_key": st.session_state.get("abuse_key", ""),
        }
        cache_snapshot = dict(st.session_state.ioc_cache)
        processed = process_single_ioc_stateless(ioc_type, ioc_value, cache_ttl_seconds, keys, cache_snapshot)
        normalized_type, normalized_value, results, source_errors, cache_hits, cache_updates = processed
        if normalized_type is None:
            st.error(source_errors[0] if source_errors else "IOC invalido.")
            return
        persist_query_outcome(normalized_type, normalized_value, results, cache_updates)

        if results:
            st.success(f"Encontrado em {len(results)} fonte(s).")
            st.json(results)
        else:
            st.warning("Nenhuma ameaca encontrada.")

        if source_errors:
            st.info("Avisos nas fontes: " + " | ".join(source_errors))
        if cache_hits:
            st.caption("Resultados via cache: " + ", ".join(cache_hits))

    st.divider()
    st.subheader("Enriquecimento Avancado (Shodan e Censys)")

    if ioc_value:
        col_sh, col_ce = st.columns(2)

        with col_sh:
            if st.button("Enriquecer com Shodan", use_container_width=True):
                if not st.session_state.get("shodan_key"):
                    st.warning("Informe a chave do Shodan na sidebar.")
                else:
                    with st.spinner("Consultando Shodan..."):
                        result, err = query_shodan(ioc_value, st.session_state["shodan_key"])
                        if result:
                            append_result_entry(ioc_type, ioc_value, result)
                            save_intel_data(st.session_state.intel_data)
                            st.success("Shodan enriquecido.")
                            st.json(result.get("extra_json", {}))
                        elif err:
                            st.error(err)
                        else:
                            st.warning("Nenhum dado retornado pelo Shodan.")

        with col_ce:
            if ioc_type == "IP" and st.button("Enriquecer com Censys", use_container_width=True):
                if not st.session_state.get("censys_token"):
                    st.warning("Informe o token do Censys na sidebar.")
                else:
                    with st.spinner("Consultando Censys..."):
                        result, err = query_censys(ioc_value, st.session_state["censys_token"])
                        if result:
                            append_result_entry(ioc_type, ioc_value, result)
                            save_intel_data(st.session_state.intel_data)
                            st.success("Censys enriquecido.")
                            st.json(result.get("extra_json", {}))
                        elif err:
                            st.error(err)
                        else:
                            st.warning("Nenhum dado retornado pelo Censys.")


def render_feed_collection():
    st.header("Coleta Automatica de Feeds")
    if st.button("Atualizar OpenPhish"):
        try:
            urls = fetch_openphish_feed(limit=100)
            for feed_url in urls:
                entry = {
                    "timestamp": now_str(),
                    "type": "URL",
                    "value": normalize_ioc_value("URL", feed_url),
                    "source": "OpenPhish Feed",
                    "risk": "Alto",
                    "risk_score": 80,
                    "details": "Phishing ativo",
                }
                upsert_intel_entry(st.session_state.intel_data, entry)
            save_intel_data(st.session_state.intel_data)
            st.success(f"Feed atualizado com {len(urls)} URLs.")
        except requests.exceptions.RequestException as exc:
            st.error(f"Erro ao baixar feed: {exc}")


def render_bulk_ioc_search(cache_ttl_seconds, batch_workers):
    st.divider()
    st.subheader("Busca em lote (CSV/TXT)")
    st.caption("CSV: colunas aceitas `type,value` ou somente `value` (usa tipo selecionado).")

    bulk_default_type = st.selectbox("Tipo padrao para lote", ["IP", "Domain", "URL", "Hash"], key="bulk_ioc_type")
    upload = st.file_uploader("Arquivo de IOCs", type=["csv", "txt"])

    if st.button("Processar lote") and upload:
        content = upload.getvalue().decode("utf-8", errors="ignore")
        ioc_items = []

        if upload.name.lower().endswith(".csv"):
            df_upload = pd.read_csv(StringIO(content))
            cols = {col.lower(): col for col in df_upload.columns}
            if "value" in cols and "type" in cols:
                for _, row in df_upload.iterrows():
                    ioc_items.append((str(row[cols["type"]]).strip(), str(row[cols["value"]]).strip()))
            elif "value" in cols:
                for _, row in df_upload.iterrows():
                    ioc_items.append((bulk_default_type, str(row[cols["value"]]).strip()))
            else:
                st.error("CSV invalido. Use coluna `value` (e opcionalmente `type`).")
                return
        else:
            for line in content.splitlines():
                line = line.strip()
                if line:
                    ioc_items.append((bulk_default_type, line))

        if not ioc_items:
            st.warning("Nenhum IOC encontrado no arquivo.")
            return

        progress = st.progress(0)
        status = st.empty()
        total = len(ioc_items)
        total_hits = 0
        total_errors = 0
        total_cache_hits = 0
        batch_entries = []

        keys = {
            "otx_key": st.session_state.get("otx_key", ""),
            "abuse_key": st.session_state.get("abuse_key", ""),
        }
        cache_snapshot = dict(st.session_state.ioc_cache)

        completed = 0
        with ThreadPoolExecutor(max_workers=batch_workers) as executor:
            future_map = {
                executor.submit(
                    process_single_ioc_stateless,
                    item_type,
                    item_value,
                    cache_ttl_seconds,
                    keys,
                    cache_snapshot,
                ): (item_type, item_value)
                for item_type, item_value in ioc_items
            }

            for future in as_completed(future_map):
                completed += 1
                src_type, src_value = future_map[future]
                status.text(f"Processando {completed}/{total}: {src_type} {src_value}")
                normalized_type, normalized_value, results, errors, cache_hits, cache_updates = future.result()

                if normalized_type is None:
                    total_errors += 1
                else:
                    total_hits += len(results)
                    total_errors += len(errors)
                    total_cache_hits += len(cache_hits)
                    persist_query_outcome(normalized_type, normalized_value, results, cache_updates)
                    for source_result in results:
                        batch_entries.append(
                            {
                                "timestamp": now_str(),
                                "type": normalized_type,
                                "value": normalized_value,
                                "source": source_result["source"],
                                "risk": source_result["risk"],
                                "risk_score": source_result.get(
                                    "risk_score", risk_to_score(source_result["risk"])
                                ),
                                "details": source_result["details"],
                            }
                        )
                progress.progress(completed / total)

        status.text("Lote concluido.")
        st.session_state.last_batch_results = batch_entries
        st.success(
            f"Lote finalizado: {total} IOCs, {total_hits} hits, {total_errors} avisos/erros, {total_cache_hits} cache hits."
        )


def render_grok_analysis(model):
    st.header("Analise Avancada com Grok")
    if not st.session_state.get("xai_key"):
        st.error("Insira sua xAI API Key na sidebar.")
        return

    if st.button("Analisar TODOS os IOCs com Grok"):
        with st.spinner("Grok analisando..."):
            try:
                client = OpenAI(api_key=st.session_state["xai_key"], base_url="https://api.x.ai/v1")
                data_str = json.dumps(st.session_state.intel_data, indent=2, ensure_ascii=False)
                prompt = (
                    "Voce e um analista de Threat Intelligence.\n"
                    "Analise os dados e forneca:\n"
                    "1. Nivel de risco geral\n"
                    "2. Atores ou campanhas provaveis\n"
                    "3. Correlacoes e vulnerabilidades\n"
                    "4. Mitigacoes recomendadas\n"
                    "5. Previsao de proximos passos\n\n"
                    f"Dados:\n{data_str}\n"
                    "Responda em portugues, claro e acionavel."
                )

                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "Especialista em ciberseguranca."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                    max_tokens=4000,
                )
                analysis = response.choices[0].message.content
                st.markdown("### Relatorio do Grok")
                st.write(analysis)

                upsert_intel_entry(
                    st.session_state.intel_data,
                    {
                        "timestamp": now_str(),
                        "type": "ANALYSIS",
                        "value": "Grok Report",
                        "source": "Grok AI",
                        "risk": "-",
                        "risk_score": 0,
                        "details": (analysis[:200] + "...") if analysis else "Sem conteudo.",
                    },
                )
                save_intel_data(st.session_state.intel_data)
            except Exception as exc:
                if "credits" in str(exc).lower() or "permission" in str(exc).lower():
                    st.error("Sua conta xAI nao tem creditos.")
                    st.markdown("[Adicionar creditos](https://console.x.ai/)")
                else:
                    st.error(f"Erro: {exc}")


def render_export():
    if st.session_state.intel_data:
        df_export = pd.DataFrame(st.session_state.intel_data)
        csv_data = df_export.to_csv(index=False).encode()
        st.download_button("Baixar Relatorio Completo (CSV)", csv_data, "phantom_report.csv", "text/csv")
    if st.session_state.get("last_batch_results"):
        df_batch = pd.DataFrame(st.session_state.last_batch_results)
        csv_batch = df_batch.to_csv(index=False).encode()
        st.download_button(
            "Baixar Somente Ultimo Lote (CSV)",
            csv_batch,
            "phantom_batch_report.csv",
            "text/csv",
        )


def main():
    st.set_page_config(page_title="PhantomIntel", page_icon="🛡️", layout="wide")
    st.title("PhantomIntel")
    st.markdown("Ferramenta de Threat Intelligence local")

    bootstrap_session()
    model, cache_ttl_seconds, batch_workers = render_sidebar()

    tab1, tab2, tab3, tab4 = st.tabs(
        ["Dashboard", "Busca IOC", "Coletar Feeds", "Analise com Grok"]
    )

    with tab1:
        render_dashboard()
    with tab2:
        render_ioc_search(cache_ttl_seconds)
        render_bulk_ioc_search(cache_ttl_seconds, batch_workers)
    with tab3:
        render_feed_collection()
    with tab4:
        render_grok_analysis(model)

    render_export()
    st.caption("PhantomIntel")


if __name__ == "__main__":
    main()

