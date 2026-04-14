COMPOSE_PROFILES=nats,controller,ws,taas,adapter,frontend,portainer docker compose up -d

# Allow external hosts to reach forwarded container ports
#sudo nft add rule ip filter DOCKER-USER ip daddr 10.10.10.0/24 ct state new accept 2>/dev/null || true
