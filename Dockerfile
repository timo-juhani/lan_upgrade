# Alpine with Python 3.10
FROM python:3.10-alpine
LABEL author="Timo-Juhani Karjalainen, tkarjala@cisco.com, Cisco CX"
LABEL description="Container for lan_upgrade"

# Upgrade packages
RUN apk update
RUN apk upgrade
ADD lan_upgrade.py /lan-upgrade/
ADD requirements.txt /lan-upgrade/
WORKDIR /lan-upgrade/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Entrypoint for the program
ENTRYPOINT ["python", "lan_upgrade.py"]