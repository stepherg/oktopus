package handler

import "net/http"

func (h *Handler) Healthcheck(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("I'm Alive"))
}
