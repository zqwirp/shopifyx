package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/lib/pq"
)

const (
	HOST        = "localhost"
	PORT        = "5432"
	DB_USER     = "postgres"
	DB_PASSWORD = "postgres" // SEPERTINYA HARUS PAKAI PASSWORD MAS
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
	r.GET("/ping", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"message": "pong"}) })
	r.POST("/pong", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"message": "ping"}) })

	v1 := r.Group("/v1")
	{
		v1.GET("/users", getUsers)
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

func registerUser(c *gin.Context) {
	var user User

	// SHOULD BIND JSON?
	if err := c.ShouldBindJSON(&user); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// ENCRYPT PASSWORD
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	// STORE USER INFO INTO DB
	if code, err := insertUserIntoDB(user.Username, user.Name, hashedPassword); err != nil {
		if code == "23505" {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// RESPONSE
	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"data": gin.H{
			"username":    user.Username,
			"name":        user.Name,
			"accessToken": "TOKEN",
		},
	})
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 8)
	return string(bytes), err // string() here converts the byte slice to a string.
}

// func checkPasswordHash(password, hash string) bool {
// 	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
// 	return err == nil
// }

func insertUserIntoDB(username, name, hashedPassword string) (pq.ErrorCode, error) {
	// CONNECT TO POSTGRES
	db, err := sql.Open(
		"postgres",
		fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			HOST, PORT, DB_USER, DB_PASSWORD, DB_NAME))
	if err != nil {
		pgErr, _ := err.(*pq.Error)
		return pgErr.Code, err
	}
	defer db.Close()

	// CHECK DB CONNECTION
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	// EXECUTE
	sqlStatement := `INSERT INTO users (username, name, password) VALUES ($1, $2, $3)`
	_, err = db.Exec(sqlStatement, username, name, hashedPassword)
	if err != nil {
		pgErr, ok := err.(*pq.Error)
		if ok && pgErr.Code == "23505" {
			return pgErr.Code, err
		}
		return pgErr.Code, err
	}

	return "", nil
}

func getUsers(c *gin.Context) {
	users, err := selectUsersFromDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve users",
		})
		return
	}

	// RESPONSE
	c.JSON(http.StatusOK, gin.H{
		"message": "Users retrieved successfully",
		"data": gin.H{
			"users": users,
		},
	})
}

func selectUsersFromDB() ([]User, error) {
	// CONNECT TO POSTGRES
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		HOST, PORT, DB_USER, DB_PASSWORD, DB_NAME))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the database: %v", err)
	}
	defer db.Close()

	// CHECK DB CONNECTION
	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to ping the database: %v", err)
	}

	// DEFINE SQL STATEMENT
	sqlStatement := `SELECT username, name FROM users`

	log.Printf("Executing SQL query: %s", sqlStatement)

	// EXECUTE
	rows, err := db.Query(sqlStatement)
	if err != nil {
		return nil, fmt.Errorf("failed to execute SQL query: %v", err)
	}
	defer rows.Close()

	// STORE QUERY RESULT TO VARIABLE
	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.Username, &user.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		users = append(users, user)
	}

	log.Println("All users selected successfully.")

	return users, nil
}
