import requests
from datetime import datetime, timedelta

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def buscar_cves(quantidade, severidade=None, dias=None, palavra=None):
    parametros = {"resultsPerPage": quantidade}

    if severidade:
        parametros["cvssV3Severity"] = severidade
    if palavra:
        parametros["keywordSearch"] = palavra
    if dias:
        fim = datetime.now()
        inicio = fim - timedelta(days=dias)
        formato = "%Y-%m-%dT%H:%M:%S.000"
        parametros["pubStartDate"] = inicio.strftime(formato)
        parametros["pubEndDate"] = fim.strftime(formato)

    try:
        resposta = requests.get(URL, params=parametros, timeout=10)
        resposta.raise_for_status()
        return resposta.json()
    except requests.exceptions.RequestException as erro:
        print(f"Erro ao buscar CVEs: {erro}")
        return None


def extrair_dados(vulnerabilidade):
    cve = vulnerabilidade.get("cve", {})

    # pega a descrição em inglês
    descricao = None
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            descricao = d.get("value")
            break

    # tenta a versão mais nova do CVSS e, se não tiver, cai para a mais antiga
    nota = None
    severidade = None
    metricas = cve.get("metrics", {})
    for versao in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lista = metricas.get(versao, [])
        if lista:
            dados_cvss = lista[0].get("cvssData", {})
            nota = dados_cvss.get("baseScore")
            severidade = dados_cvss.get("baseSeverity") or lista[0].get("baseSeverity")
            break

    return {
        "id": cve.get("id"),
        "descricao": descricao,
        "nota": nota,
        "severidade": severidade,
    }


def filtrar_por_nota(lista, minimo):
    resultado = []
    for cve in lista:
        if cve["nota"] is not None and cve["nota"] >= minimo:
            resultado.append(cve)
    return resultado


def ordenar_por_nota(lista):
    return sorted(
        lista,
        key=lambda cve: cve["nota"] if cve["nota"] is not None else 0,
        reverse=True,
    )


def main():
    # ===== ESCOLHA AQUI O QUE VOCÊ QUER =====
    QUANTIDADE = 50        # quantos CVEs pedir
    SEVERIDADE = "CRITICAL"  # "LOW", "MEDIUM", "HIGH", "CRITICAL" ou None para todas
    DIAS = 30              # publicados nos últimos X dias (máximo 120) ou None
    PALAVRA = None         # ex.: "windows", "remote code execution" ou None
    NOTA_MINIMA = 0        # filtro extra de nota, de 0 a 10
    # ========================================

    dados = buscar_cves(QUANTIDADE, SEVERIDADE, DIAS, PALAVRA)
    if dados is None:
        return

    cves = []
    for vulnerabilidade in dados.get("vulnerabilities", []):
        cves.append(extrair_dados(vulnerabilidade))

    filtrados = filtrar_por_nota(cves, NOTA_MINIMA)
    filtrados = ordenar_por_nota(filtrados)

    print(f"{len(filtrados)} CVEs encontrados\n")
    for cve in filtrados:
        print(f'{cve["id"]} | nota {cve["nota"]} | {cve["severidade"]}')
        print(f'   {(cve["descricao"] or "")[:150]}\n')
    
if __name__ == "__main__":
    main()