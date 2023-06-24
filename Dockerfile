FROM python:3.9.17-alpine3.18

ARG POETRY_VERSION=1.4.2

# Removes caching and warning messages from pip
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

COPY . .

RUN python3 -m pip install "poetry==${POETRY_VERSION}" && \
    poetry config virtualenvs.create false && \
    poetry install --without dev && \
    ln -s /root/.config /config

WORKDIR /data

ENTRYPOINT [ "nut" ]

