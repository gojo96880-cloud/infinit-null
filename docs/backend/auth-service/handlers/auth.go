package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type RegisterResponse struct {
	UserID    int64     `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func LoginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	response := LoginResponse{
		AccessToken:  "generated_jwt_token",
		RefreshToken: "generated_refresh_token",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
	}
	c.JSON(http.StatusOK, response)
}

func RegisterHandler(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	response := RegisterResponse{
		UserID:    1,
		Username:  req.Username,
		Email:     req.Email,
		CreatedAt: time.Now(),
	}
	c.JSON(http.StatusCreated, response)
}

func RefreshTokenHandler(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	response := LoginResponse{
		AccessToken:  "new_jwt_token",
		RefreshToken: req.RefreshToken,
		ExpiresIn:    3600,
		TokenType:    "Bearer",
	}
	c.JSON(http.StatusOK, response)
}

func LogoutHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}
