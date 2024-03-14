package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
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

var JWT_SECRET_KEY []byte = []byte("ONTA")

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
		v1.POST("/user/register", registerUser)
		v1.POST("/user/login", loginUser)
		v1.GET("/users", getUsers)
	}
	// END OF ROUTES

	r.Run(":8000")
}

func registerUser(c *gin.Context) {
	var user RegisterUserRequestBody

	// SHOULD BIND JSON?
	if err := c.ShouldBindJSON(&user); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// HASH PASSWORD
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

	// GENERATE TOKEN
	token, err := generateToken(user.Username, user.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// RESPONSE
	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"data": gin.H{
			"username":    user.Username,
			"name":        user.Name,
			"accessToken": token,
		},
	})
}

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

func loginUser(c *gin.Context) {
	var body LoginUserRequestBody

	// SHOULD BIND JSON?
	if err := c.ShouldBindJSON(&body); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	var user User

	// RETRIVE USER
	if err := user.selectUserByUsername(body.Username); err != nil {
		if err == sql.ErrNoRows {
			c.Status(http.StatusNotFound)
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	// CHECK PASSWORD
	err := checkPasswordHash(body.Password, user.Password)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// GENERATE TOKEN
	token, err := generateToken(user.Username, user.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// RESPONSE
	c.JSON(http.StatusOK, gin.H{
		"message": "User logged successfully",
		"data": gin.H{
			"username":    user.Username,
			"name":        user.Name,
			"accessToken": token,
		},
	})
}

func (u *User) selectUserByUsername(username string) error {
	// CONNECT TO POSTGRES
	db, err := sql.Open(
		"postgres",
		fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			HOST, PORT, DB_USER, DB_PASSWORD, DB_NAME))
	if err != nil {
		return err
	}
	defer db.Close()

	// EXECUTE
	sqlStatement := `SELECT * FROM users WHERE username=$1`
	row := db.QueryRow(sqlStatement, username)

	// SCAN THE ROW INTO A USER STRUCT
	err = row.Scan(&u.ID, &u.Username, &u.Name, &u.Password, &u.CreatedAt)
	if err != nil {
		return err
	}

	return nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 8)
	return string(bytes), err // string() here converts the byte slice to a string.
}

func checkPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func generateToken(username, name string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"name":     name,
		"exp":      time.Now().Add(2 * time.Minute).Unix(),
	})

	tokenString, err := t.SignedString(JWT_SECRET_KEY)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	// PARSE THE TOKEN
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// VALIDATE THE SIGNING METHOD
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return JWT_SECRET_KEY, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	// CHECK IF THE TOKEN IS VALID
	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	// CHECK IF THE TOKEN IS EXPIRED
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid expiration time")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("token has expired")
	}

	return claims, nil
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

func selectUsersFromDB() ([]RegisterUserRequestBody, error) {
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
	var users []RegisterUserRequestBody
	for rows.Next() {
		var user RegisterUserRequestBody
		err := rows.Scan(&user.Username, &user.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		users = append(users, user)
	}

	log.Println("All users selected successfully.")

	return users, nil
}

/*
STRUCTS
*/
type RegisterUserRequestBody struct {
	Username string `json:"username" binding:"required,min=5,max=15"`
	Name     string `json:"name" binding:"required,min=5,max=50"`
	Password string `json:"password" binding:"required,min=5,max=15"`
}

type LoginUserRequestBody struct {
	Username string `json:"username" binding:"required,min=5,max=15"`
	Password string `json:"password" binding:"required,min=5,max=15"`
}

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Name      string    `json:"name"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
}
