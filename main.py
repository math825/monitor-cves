import requests

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def buscar_cves(quantidade):
    parametros = {"resultsPerPage": quantidade}
    try:
        resposta = requests.get(URL, params=parametros, timeout=10)
        resposta.raise_for_status()
        return resposta.json()
    except requests.exceptions.RequestException as erro:
        print(f"Erro ao buscar CVEs: {erro}")
        return None

def main():
    dados = buscar_cves(5)
    if dados is None:
        return
    for c in dados.get("vulnerabilities", []):
        print(c.get("cve", {}).get("id"))

if __name__ == "__main__":
    main()