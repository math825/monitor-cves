import requests

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def buscar_cves(quantidade):
    parametros = {"resultsPerPage": quantidade}
    resposta = requests.get(URL, params=parametros)
    return resposta.json()

def main():
    dados = buscar_cves(20)
    for c in dados.get("vulnerabilities", []):
        print(c.get("cve", {}).get("id"))


if __name__ == "__main__":
    main()