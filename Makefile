
CHART=chart/ingress-saml-authorizer/Chart.yaml
VALUES=chart/ingress-saml-authorizer/values.yaml

REPOSITORY:=$(shell python3 scripts/repository.py $(VALUES))
VERSION:=$(shell python3 scripts/version.py $(CHART))

build:
	docker build -t $(REPOSITORY):$(VERSION) .

load:
	kind load docker-image $(REPOSITORY):$(VERSION)

authorizer.cert:
	openssl req -x509 -newkey rsa:2048 -keyout authorizer.key -out authorizer.cert -days 365 -nodes -subj "/CN=authorizer.example.com"

authorizer.xml:
	curl localhost:8000/saml/metadata > $@

clean:
	rm -f authorizer.key authorizer.cert ingress-saml-authorizer-$(VERSION).tgz 
	rm -rf output/

package: output output/index.yaml

output/index.yaml: output/ingress-saml-authorizer-$(VERSION).tgz
	helm repo index output/

output/ingress-saml-authorizer-$(VERSION).tgz: ingress-saml-authorizer-$(VERSION).tgz
	cp -f ingress-saml-authorizer-$(VERSION).tgz output/

ingress-saml-authorizer-$(VERSION).tgz:
	helm package chart/ingress-saml-authorizer

output:
	mkdir -p output/