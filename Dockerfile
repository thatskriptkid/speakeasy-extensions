FROM python:3.11-slim

ARG SPEAKEASY_VERSION=1.5.11

ENV PYTHONUNBUFFERED=1 \
    PYTHONWARNINGS="ignore:pkg_resources is deprecated as an API:UserWarning" \
    PIP_NO_CACHE_DIR=1

RUN python -m pip install --upgrade pip "setuptools<81" wheel \
    && python -m pip install "speakeasy-emulator==${SPEAKEASY_VERSION}"

COPY patches/patch_speakeasy.py /tmp/patch_speakeasy.py
RUN python /tmp/patch_speakeasy.py && rm /tmp/patch_speakeasy.py

WORKDIR /sandbox

CMD ["speakeasy", "-h"]
