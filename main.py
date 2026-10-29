import requests

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
parametros = {"resultsPerPage": 5}

resposta = requests.get(url, params=parametros)

print(resposta.status_code)
print(resposta.url)
dados = resposta.json()
print(type(dados))
print(dados.keys())
for c in dados.get("vulnerabilities",[]):
    print(c.get("cve", {}).get("id"))