package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

type GithubAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type GithubUserData struct {
	Username  string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

var githubClientID string
var githubClientSecret string

func init() {
	var exists bool
	// Load values from env on init
	githubClientID, exists = os.LookupEnv("GITHUB_CLIENT_ID")
	if !exists {
		log.Fatalln("GITHUB_CLIENT_ID not defined.")
	}
	githubClientSecret, exists = os.LookupEnv("GITHUB_CLIENT_SECRET")
	if !exists {
		log.Fatalln("GITHUB_CLIENT_SECRET not defined.")
	}
}

func main() {
	// Login route
	http.HandleFunc("/auth/github", githubAuthHandler)

	// GitHub callback
	http.HandleFunc("/auth/github/callback", githubAuthCallbackHandler)

	// Listen and serve on port 3000
	fmt.Println("Listening on port :3000")
	log.Fatalln(http.ListenAndServe(":3000", nil))
}

func githubAuthHandler(w http.ResponseWriter, r *http.Request) {
	redirectURI := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s",
		githubClientID,
		"http://localhost:3000/auth/github/callback",
	)
	http.Redirect(w, r, redirectURI, http.StatusMovedPermanently)
}

func githubAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	accessToken := getGithubAccessToken(code)
	userData := getGithubUserData(accessToken)

	response, _ := json.Marshal(userData)
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func getGithubAccessToken(code string) string {
	payload, _ := json.Marshal(map[string]string{
		"client_id":     githubClientID,
		"client_secret": githubClientSecret,
		"code":          code,
	})

	req, err := http.NewRequest(
		http.MethodPost,
		"https://github.com/login/oauth/access_token",
		bytes.NewBuffer(payload),
	)
	if err != nil {
		log.Panicln("Failed to create a request", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Fetch the access token
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Panicln("Failed to fetch access token", err)
	}

	resPayload := GithubAccessTokenResponse{}
	err = json.NewDecoder(res.Body).Decode(&resPayload)
	if err != nil {
		log.Panicln("Invalid reponse payload")
	}
	defer res.Body.Close()

	return resPayload.AccessToken
}

func getGithubUserData(accessToken string) *GithubUserData {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		log.Fatalln("Failed to create a request", err)
	}

	req.Header.Set("Authorization", "token "+accessToken)

	// Fetch the user data using the access token
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Panicln("Failed to fetch user", err)
	}

	userData := GithubUserData{}
	err = json.NewDecoder(res.Body).Decode(&userData)
	if err != nil {
		log.Panicln("Invalid reponse payload")
	}
	defer res.Body.Close()

	return &userData
}
