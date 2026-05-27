package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	log.Println("Starting API Gateway")

	router := gin.Default()

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	authGroup := router.Group("/api/v1/auth")
	{
		authGroup.POST("/register", func(c *gin.Context) {
			c.JSON(http.StatusCreated, gin.H{"message": "User registered"})
		})
		authGroup.POST("/login", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "Logged in"})
		})
		authGroup.POST("/refresh", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "Token refreshed"})
		})
	}

	threatGroup := router.Group("/api/v1/threats")
	{
		threatGroup.GET("/", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "Threats list"})
		})
		threatGroup.GET("/:id", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "Threat details"})
		})
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("API Gateway listening on port %s\n", port)
	router.Run(":" + port)
}
