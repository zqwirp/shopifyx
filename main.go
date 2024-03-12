package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq" // Import the PostgreSQL driver
)

const (
	HOST        = "localhost"
	PORT        = "5432"
	DB_USER     = "postgres"
	DB_PASSWORD = ""
	DB_NAME     = "shopifyx_sprint"
)

func main() {
	r := gin.Default()

	// CORS CONFIG
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"*"},
		AllowCredentials: true,
	}))

	// ROUTES
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.POST("/pong", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "ping",
		})
	})

	v1 := r.Group("/v1")
	{
		v1.POST("/user/register", registerUser)
	}
	// END OF ROUTES

	r.Run(":8000")
}

type User struct {
	Username string `json:"username" binding:"required,min=5,max=15"`
	Name     string `json:"name" binding:"required,min=5,max=50"`
	Password string `json:"password" binding:"required,min=5,max=15"`
}

// "username": "seseorang", // not null, minLength 5, maxLength 15
// "name": "namadepan namabelakang", // not null, minLength 5, maxLength 50
// "password": "" // not null, minLength 5, maxLength 15

func registerUser(c *gin.Context) {
	var user User

	// SHOULD BIND JSON?
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	if err := insertUserIntoDB(user.Username, user.Name, hashedPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.SetCookie("accessToken", "THE_TOKEN", 3600, "/", "", false, true)

	// RESPONSE
	c.JSON(http.StatusOK, gin.H{
		"message": "User registered successfully",
		"data": gin.H{
			"user": user,
		},
	})
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 8)
	return string(bytes), err // string() here converts the byte slice to a string.
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func insertUserIntoDB(username, name, hashedPassword string) error {
	// ESTABLISH A CONNECTION TO THE POSTGRESQL DATABASE
	fmt.Println("Connecting to the database...")
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		HOST, PORT, DB_USER, DB_PASSWORD, DB_NAME))
	if err != nil {
		fmt.Println("Error executing SQL query:", err)
		return err
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	sqlStatement := `INSERT INTO users (username, name, password) VALUES ($1, $2, $3)`
	fmt.Println("Executing SQL query...")
	fmt.Printf("Executing query: %s\n", sqlStatement)
	fmt.Printf("Parameters: Username: %s, Name: %s, Hashed Password: %s\n", username, name, hashedPassword)
	// EXECUTE THE SQL QUERY TO INSERT A NEW USER
	_, err = db.Exec(sqlStatement, username, name, hashedPassword)
	// _, err = db.Exec(sqlStatement)
	if err != nil {
		return err
	}

	return nil
}
