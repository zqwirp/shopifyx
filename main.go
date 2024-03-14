package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// ENCRYPT PASSWORD
	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	// STORE USER INFO INTO DB
	if err := insertUserIntoDB(user.Username, user.Name, hashedPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	// TEST SET COOKIE
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
	// CONNECT TO POSTGRES
	fmt.Println("Connecting to the database...")
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		HOST, PORT, DB_USER, DB_PASSWORD, DB_NAME))
	if err != nil {
		fmt.Println("Error executing SQL query:", err)
		return err
	}
	defer db.Close()

	// CHECK DB CONNECTION
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	sqlStatement := `INSERT INTO users (username, name, password) VALUES ($1, $2, $3)`
	fmt.Printf("Executing query: %s\n", sqlStatement)
	fmt.Printf("Parameters: Username: %s, Name: %s, Hashed Password: %s\n", username, name, hashedPassword)

	// EXECUTE
	_, err = db.Exec(sqlStatement, username, name, hashedPassword)
	if err != nil {
		return err
	}

	return nil
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
