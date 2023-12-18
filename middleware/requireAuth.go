package middleware

import (
	"GoJWTAuthentication/initializers"
	"GoJWTAuthentication/models"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(c *gin.Context) {
	// Get cookie off request
	tokenString, err := c.Cookie("Authorization")

	fmt.Println(tokenString, err)

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	} else {
		// Decode/validate cookie
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("SECRET")), nil
		})

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Check exp
			if float64(time.Now().Unix()) > claims["exp"].(float64) {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			// Find user with token sub
			var user models.User
			initializers.DB.First(&user, claims["sub"])

			if user.ID == 0 {
				c.AbortWithStatus(http.StatusUnauthorized)
			}

			// Attach user to context
			c.Set("user", user)

			// Continue
			c.Next()
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}

}
