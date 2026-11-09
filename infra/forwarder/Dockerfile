# Minimal trusted TCP relay for CyberLab challenge instances.
#
# Challenge containers live on the internal `cyberlab_labs` network and cannot
# reach the internet. Docker refuses to publish ports for containers that are
# only attached to an internal network, so each instance gets one of these
# forwarders. The forwarder is attached to both the internal lab network and a
# normal edge network, publishes the host port, and relays to the challenge.
#
# The relay is infrastructure, not a challenge. It runs as a non-root user with
# no capabilities and a read-only filesystem.

FROM alpine:3.21

RUN apk add --no-cache socat \
    && addgroup -g 1000 relay \
    && adduser -D -u 1000 -G relay relay

USER 1000:1000

ENTRYPOINT ["socat"]
CMD ["TCP-LISTEN:8000,fork,reuseaddr", "TCP:target:8000"]
