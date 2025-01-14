package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	_ "github.com/go-oauth2/mysql"
	"github.com/go-oauth2/oauth2/manage"
	"github.com/go-oauth2/oauth2/models"
	"github.com/go-oauth2/oauth2/server"
	"github.com/go-oauth2/oauth2/store"
	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/errors"
)

func main() {

	//db, err := sql.Open("mysql", "felipe:felipe@/goauth2")
	//if err != nil {
	//	log.Fatal(err)
	//}
	//storage := mysql.NewStoreWithDB(db, "tokens", 0)

	m := manage.NewDefaultManager()
	m.MustTokenStorage(store.NewMemoryTokenStore())

	clientStorage := store.NewClientStore()
	var client = models.Client{ID: "Client", Secret: "secret", UserID: "user3", Domain: "http://localhost"}
	clientStorage.Set("Client", &client)

	m.MapClientStorage(clientStorage)
	srv := server.NewDefaultServer(m)
	srv.SetAllowedGrantType(oauth2.ClientCredentials)

	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(server.InternalErrorHandler(func(err error) (re *errors.Response) {
		return errors.NewResponse(err, 500)
	}))

	TokenHandler := func(w http.ResponseWriter, r *http.Request) {

		srv.HandleTokenRequest(w, r)

	}

	ProtectedHandler := func(w http.ResponseWriter, r *http.Request) {

		w.Write([]byte("Entering protected route!"))

	}

	AuthMiddleware := func(next http.HandlerFunc) http.HandlerFunc {

		return func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			fmt.Println(token)
			if token == "" {
				w.WriteHeader(400)
				w.Write([]byte("Empty token"))
				return
			}
			t := strings.Split(token, " ")

			if t[0] != "Bearer" {
				w.WriteHeader(400)
				w.Write([]byte("Not a bearer token"))
				return

			}

			client, err := srv.ValidationBearerToken(r)
			if err != nil {
				w.WriteHeader(400)
				w.Write([]byte(err.Error()))
				return

			}

			json.NewEncoder(w).Encode(client)
			next(w, r)

		}

	}

	http.Handle("POST /token/", http.HandlerFunc(TokenHandler))
	http.Handle("/", http.HandlerFunc(AuthMiddleware(ProtectedHandler)))
	http.ListenAndServe(":5000", nil)

}
