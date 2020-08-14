package web

import (
	"time"
	"github.com/gin-gonic/gin"
	"github.com/dgrijalva/jwt-go"
)


var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Login(c *gin.Context) {
	var data map[string]string
	err := c.BindJSON(&data)
	if err != nil {
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(69 * time.Hour)
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		Username: "admin",
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(404, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"token": tokenString,
	})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tknStr := c.GetHeader("Authorization")

		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			c.JSON(400, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

		if !tkn.Valid {
			c.JSON(400, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

		if claims.Username != "admin" {
			c.Abort()
			return
		}

		c.Next()
	}
}
