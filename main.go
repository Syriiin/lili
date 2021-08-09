package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var hmacSecret = []byte(os.Getenv("SECRET_KEY"))

type server struct {
	dbpool *pgxpool.Pool
}

func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("welcome to lili"))
}

type AuthRequestData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponseData struct {
	Token string `json:"token"`
}

func generateToken(userId int, username string) (string, error) {
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":   userId,
		"username": username,
		"iat":      now.Unix(),
		"exp":      now.Add(30 * 24 * time.Hour).Unix(),
	})
	return token.SignedString(hmacSecret)
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var requestData AuthRequestData
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	now := time.Now().UTC()
	var userId int
	err = s.dbpool.QueryRow(context.Background(), "INSERT INTO users (username, password_salted_hash, created_at, last_login) VALUES ($1, $2, $3, $4) RETURNING id", requestData.Username, string(hash), now, now).Scan(&userId)
	if err != nil {
		panic(err)
	}

	token, err := generateToken(userId, requestData.Username)
	if err != nil {
		panic(err)
	}
	responseData := &AuthResponseData{Token: token}
	b, err := json.Marshal(responseData)
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var requestData AuthRequestData
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var userId int
	var hash string
	err = s.dbpool.QueryRow(context.Background(), "SELECT id, password_salted_hash FROM users WHERE username = $1", requestData.Username).Scan(&userId, &hash)
	if err != nil {
		http.Error(w, "Unauthorised", http.StatusUnauthorized)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(requestData.Password))
	if err != nil {
		http.Error(w, "Unauthorised", http.StatusUnauthorized)
		return
	}

	now := time.Now().UTC()
	_, err = s.dbpool.Exec(context.Background(), "UPDATE users SET last_login = $1 WHERE username = $2", now, requestData.Username)
	if err != nil {
		panic(err)
	}

	token, err := generateToken(userId, requestData.Username)
	if err != nil {
		panic(err)
	}
	responseData := &AuthResponseData{Token: token}
	b, err := json.Marshal(responseData)
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

func verifyToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return hmacSecret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("token invalid")
	}

	return claims, nil
}

type MeResponseData struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
	if len(authHeader) != 2 {
		http.Error(w, "Unauthorised", http.StatusUnauthorized)
		return
	}

	claims, err := verifyToken(authHeader[1])
	if err != nil {
		http.Error(w, "Unauthorised", http.StatusUnauthorized)
		return
	}

	userId := int(claims["userId"].(float64))
	username := claims["username"].(string)
	responseData := &MeResponseData{Id: userId, Username: username}
	b, err := json.Marshal(responseData)
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

type requestContextKey int

const tokenClaimsKey requestContextKey = 0

type TokenClaims struct {
	UserId   int    `json:"userId"`
	Username string `json:"username"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
}

func parseClaims(claims jwt.MapClaims) TokenClaims {
	return TokenClaims{
		UserId:   int(claims["userId"].(float64)),
		Username: claims["username"].(string),
		IssuedAt: int64(claims["iat"].(float64)),
		Expiry:   int64(claims["exp"].(float64)),
	}
}

func tokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
		if len(authHeader) != 2 {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
			return
		}

		claims, err := verifyToken(authHeader[1])
		if err != nil {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), tokenClaimsKey, parseClaims(claims))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type LilipadShortResponseData struct {
	Id        int       `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type LilipadResponseData struct {
	Id        int       `json:"id"`
	Name      string    `json:"name"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (s *server) handleListLilipads(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(tokenClaimsKey).(TokenClaims)

	lilipads := []LilipadShortResponseData{}
	rows, err := s.dbpool.Query(context.Background(), "SELECT id, name, created_at, updated_at FROM lilipads WHERE user_id = $1", claims.UserId)
	if err != nil {
		panic(err)
	}
	for rows.Next() {
		lilipad := LilipadShortResponseData{}

		err := rows.Scan(&lilipad.Id, &lilipad.Name, &lilipad.CreatedAt, &lilipad.UpdatedAt)
		if err != nil {
			panic(err)
		}

		lilipads = append(lilipads, lilipad)
	}

	b, err := json.Marshal(lilipads)
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

type CreateLilipadRequestData struct {
	Name string `json:"name"`
}

func (s *server) handleCreateLilipad(w http.ResponseWriter, r *http.Request) {
	var requestData CreateLilipadRequestData
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	claims := r.Context().Value(tokenClaimsKey).(TokenClaims)

	now := time.Now().UTC()
	var id int
	err = s.dbpool.QueryRow(context.Background(), "INSERT INTO lilipads (user_id, name, text, created_at, updated_at) VALUES ($1, $2, $3, $4, $5) RETURNING id", claims.UserId, requestData.Name, "", now, now).Scan(&id)
	if err != nil {
		panic(err)
	}

	lilipad := LilipadResponseData{Id: id, Name: requestData.Name, Text: "", CreatedAt: now, UpdatedAt: now}
	b, err := json.Marshal(lilipad)
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

func (s *server) handleGetLilipad(w http.ResponseWriter, r *http.Request) {
	lilipadId, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		panic(err)
	}

	claims := r.Context().Value(tokenClaimsKey).(TokenClaims)

	lilipad := LilipadResponseData{}
	err = s.dbpool.QueryRow(context.Background(), "SELECT id, name, text, created_at, updated_at FROM lilipads WHERE user_id = $1 AND id = $2", claims.UserId, lilipadId).Scan(&lilipad.Id, &lilipad.Name, &lilipad.Text, &lilipad.CreatedAt, &lilipad.UpdatedAt)
	if err == pgx.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		panic(err)
	}

	b, err := json.Marshal(lilipad)
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

type UpdateLilipadRequestData struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

func (s *server) handleUpdateLilipad(w http.ResponseWriter, r *http.Request) {
	lilipadId, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		panic(err)
	}

	var requestData UpdateLilipadRequestData
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	claims := r.Context().Value(tokenClaimsKey).(TokenClaims)

	var id int
	var createdAt time.Time
	err = s.dbpool.QueryRow(context.Background(), "SELECT id, created_at FROM lilipads WHERE user_id = $1 AND id = $2", claims.UserId, lilipadId).Scan(&id, &createdAt)
	if err == pgx.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		panic(err)
	}

	now := time.Now().UTC()
	_, err = s.dbpool.Exec(context.Background(), "UPDATE lilipads SET name = $1, text = $2, updated_at = $3 WHERE user_id = $4 AND id = $5", requestData.Name, requestData.Text, now, claims.UserId, id)
	if err != nil {
		panic(err)
	}

	lilipad := LilipadResponseData{Id: id, Name: requestData.Name, Text: requestData.Text, CreatedAt: createdAt, UpdatedAt: now}
	b, err := json.Marshal(lilipad)
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

func (s *server) handleDeleteLilipad(w http.ResponseWriter, r *http.Request) {
	lilipadId, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		panic(err)
	}

	claims := r.Context().Value(tokenClaimsKey).(TokenClaims)

	var id int
	err = s.dbpool.QueryRow(context.Background(), "SELECT id FROM lilipads WHERE user_id = $1 AND id = $2", claims.UserId, lilipadId).Scan(&id)
	if err == pgx.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		panic(err)
	}

	_, err = s.dbpool.Exec(context.Background(), "DELETE FROM lilipads WHERE user_id = $1 AND id = $2", claims.UserId, lilipadId)
	if err != nil {
		panic(err)
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	url := os.Getenv("DATABASE_URL")
	dbpool, err := pgxpool.Connect(context.Background(), url)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer dbpool.Close()

	s := server{dbpool: dbpool}
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Route("/api", func(r chi.Router) {
		r.Get("/", s.handleHome)
		r.Post("/register", s.handleRegister)
		r.Post("/login", s.handleLogin)
		r.Get("/me", s.handleMe)
		r.Route("/lilipads", func(r chi.Router) {
			r.Use(tokenMiddleware)
			r.Get("/", s.handleListLilipads)
			r.Post("/", s.handleCreateLilipad)
			r.Get("/{id:\\d+}", s.handleGetLilipad)
			r.Put("/{id:\\d+}", s.handleUpdateLilipad)
			r.Delete("/{id:\\d+}", s.handleDeleteLilipad)
		})
	})

	log.Println("Listening on port 4000...")
	log.Fatal(http.ListenAndServe(":4000", r))
}
