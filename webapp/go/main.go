package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"maps"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-json-experiment/json"
	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/isucon/isucon11-qualify/isucondition/isuutil"
	"github.com/jmoiron/sqlx"
	"github.com/kaz/pprotein/integration/echov4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/otel"
)

const (
	sessionName                 = "isucondition_go"
	conditionLimit              = 20
	frontendContentsPath        = "../public"
	iconDir                     = "../public/icon"
	jiaJWTSigningKeyPath        = "../ec256-public.pem"
	defaultIconFilePath         = "../NoImage.jpg"
	defaultJIAServiceURL        = "http://localhost:5000"
	mysqlErrNumDuplicateEntry   = 1062
	conditionLevelInfo          = "info"
	conditionLevelWarning       = "warning"
	conditionLevelCritical      = "critical"
	scoreConditionLevelInfo     = 3
	scoreConditionLevelWarning  = 2
	scoreConditionLevelCritical = 1
)

var (
	db                  *sqlx.DB
	sessionStore        sessions.Store
	mySQLConnectionData *MySQLConnectionEnv

	jiaJWTSigningKey *ecdsa.PublicKey

	postIsuConditionTargetBaseURL string // JIAへのactivate時に登録する，ISUがconditionを送る先のURL

	conditionCache = sync.Map{}
	isuCache       = sync.Map{}
	userCache      = sync.Map{}
	JIAServiceURL  = ""
)

type Config struct {
	Name string `db:"name"`
	URL  string `db:"url"`
}

type User struct {
	JIAUserID string    `db:"jia_user_id"`
	CreatedAt time.Time `db:"created_at"`
}

type Isu struct {
	ID         int       `db:"id" json:"id"`
	JIAIsuUUID string    `db:"jia_isu_uuid" json:"jia_isu_uuid"`
	Name       string    `db:"name" json:"name"`
	Image      []byte    `db:"image" json:"-"`
	Character  string    `db:"character" json:"character"`
	JIAUserID  string    `db:"jia_user_id" json:"-"`
	CreatedAt  time.Time `db:"created_at" json:"-"`
	UpdatedAt  time.Time `db:"updated_at" json:"-"`
}

type IsuFromJIA struct {
	Character string `json:"character"`
}

type GetIsuListResponse struct {
	ID                 int                      `json:"id"`
	JIAIsuUUID         string                   `json:"jia_isu_uuid"`
	Name               string                   `json:"name"`
	Character          string                   `json:"character"`
	LatestIsuCondition *GetIsuConditionResponse `json:"latest_isu_condition"`
}

type IsuCondition struct {
	ID             int       `db:"id"`
	JIAIsuUUID     string    `db:"jia_isu_uuid"`
	Timestamp      time.Time `db:"timestamp"`
	IsSitting      bool      `db:"is_sitting"`
	Condition      string    `db:"condition"`
	Message        string    `db:"message"`
	CreatedAt      time.Time `db:"created_at"`
	ConditionLevel string    `db:"condition_level"`
}

type MySQLConnectionEnv struct {
	Host     string
	Port     string
	User     string
	DBName   string
	Password string
}

type InitializeRequest struct {
	JIAServiceURL string `json:"jia_service_url"`
}

type InitializeResponse struct {
	Language string `json:"language"`
}

type GetMeResponse struct {
	JIAUserID string `json:"jia_user_id"`
}

type GraphResponse struct {
	StartAt             int64           `json:"start_at"`
	EndAt               int64           `json:"end_at"`
	Data                *GraphDataPoint `json:"data"`
	ConditionTimestamps []int64         `json:"condition_timestamps"`
}

type GraphDataPoint struct {
	Score      int                  `json:"score"`
	Percentage ConditionsPercentage `json:"percentage"`
}

type ConditionsPercentage struct {
	Sitting      int `json:"sitting"`
	IsBroken     int `json:"is_broken"`
	IsDirty      int `json:"is_dirty"`
	IsOverweight int `json:"is_overweight"`
}

type GraphDataPointWithInfo struct {
	JIAIsuUUID          string
	StartAt             time.Time
	Data                GraphDataPoint
	ConditionTimestamps []int64
}

type GetIsuConditionResponse struct {
	JIAIsuUUID     string `json:"jia_isu_uuid"`
	IsuName        string `json:"isu_name"`
	Timestamp      int64  `json:"timestamp"`
	IsSitting      bool   `json:"is_sitting"`
	Condition      string `json:"condition"`
	ConditionLevel string `json:"condition_level"`
	Message        string `json:"message"`
}

type TrendResponse struct {
	Character string            `json:"character"`
	Info      []*TrendCondition `json:"info"`
	Warning   []*TrendCondition `json:"warning"`
	Critical  []*TrendCondition `json:"critical"`
}

type TrendCondition struct {
	ID        int   `json:"isu_id"`
	Timestamp int64 `json:"timestamp"`
}

type PostIsuConditionRequest struct {
	IsSitting bool   `json:"is_sitting"`
	Condition string `json:"condition"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

type JIAServiceRequest struct {
	TargetBaseURL string `json:"target_base_url"`
	IsuUUID       string `json:"isu_uuid"`
}

func getEnv(key string, defaultValue string) string {
	val := os.Getenv(key)
	if val != "" {
		return val
	}
	return defaultValue
}

func NewMySQLConnectionEnv() *MySQLConnectionEnv {
	return &MySQLConnectionEnv{
		Host:     getEnv("MYSQL_HOST", "127.0.0.1"),
		Port:     getEnv("MYSQL_PORT", "3306"),
		User:     getEnv("MYSQL_USER", "isucon"),
		DBName:   getEnv("MYSQL_DBNAME", "isucondition"),
		Password: getEnv("MYSQL_PASS", "isucon"),
	}
}

func (mc *MySQLConnectionEnv) ConnectDB() (*sqlx.DB, error) {
	dsn := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?parseTime=true&loc=Asia%%2FTokyo", mc.User, mc.Password, mc.Host, mc.Port, mc.DBName)
	return sqlx.Open("mysql", dsn)
}

func initCache() error {
	var query string

	JIAServiceURL = ""
	isuCache.Clear()
	conditionCache.Clear()
	userCache.Clear()

	var config Config
	err := db.Get(&config, "SELECT * FROM `isu_association_config` WHERE `name` = ?", "jia_service_url")
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Print(err)
		}
		JIAServiceURL = defaultJIAServiceURL
	}
	JIAServiceURL = config.URL

	var isuList []Isu
	query = "SELECT * FROM `isu`"
	if err := db.Select(&isuList, query); err != nil {
		return err
	}
	for _, isu := range isuList {
		isuCache.Store(isu.JIAIsuUUID, isu)
		var lastCondition IsuCondition
		err := db.Get(&lastCondition, "SELECT * FROM `isu_condition` WHERE `jia_isu_uuid` = ? ORDER BY `timestamp` DESC LIMIT 1",
			isu.JIAIsuUUID)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		} else {
			nextCondition, ok := conditionCache.Load(isu.JIAIsuUUID)
			if ok && nextCondition.(IsuCondition).Timestamp.Before(lastCondition.Timestamp) {

			} else {
				conditionCache.Store(isu.JIAIsuUUID, lastCondition)
			}
		}
	}

	var userList []User
	query = "SELECT * FROM `user`"
	if err := db.Select(&userList, query); err != nil {
		return err
	}
	for _, user := range userList {
		userCache.Store(user.JIAUserID, user)
	}

	return nil
}

func init() {
	sessionStore = sessions.NewCookieStore([]byte(getEnv("SESSION_KEY", "isucondition")))

	key, err := ioutil.ReadFile(jiaJWTSigningKeyPath)
	if err != nil {
		log.Fatalf("failed to read file: %v", err)
	}
	jiaJWTSigningKey, err = jwt.ParseECPublicKeyFromPEM(key)
	if err != nil {
		log.Fatalf("failed to parse ECDSA public key: %v", err)
	}
}

type v2JSONSerializer struct {
}

func (s *v2JSONSerializer) Serialize(c echo.Context, i interface{}, indent string) error {
	return json.MarshalWrite(c.Response(), i)
}

func (s *v2JSONSerializer) Deserialize(c echo.Context, i interface{}) error {
	return json.UnmarshalRead(c.Request().Body, i)
}

func main() {
	e := echo.New()
	e.Debug = true
	e.Logger.SetLevel(log.DEBUG)

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	echov4.EnableDebugHandler(e)
	_, err := isuutil.InitializeTracerProvider()
	if err != nil {
		panic(err)
	}
	e.Use(otelecho.Middleware("webapp"))
	e.JSONSerializer = &v2JSONSerializer{}

	e.POST("/initialize", postInitialize)

	e.POST("/api/auth", postAuthentication)
	e.POST("/api/signout", postSignout)
	e.GET("/api/user/me", getMe)
	e.GET("/api/isu", getIsuList)
	e.POST("/api/isu", postIsu)
	e.GET("/api/isu/:jia_isu_uuid", getIsuID)
	e.GET("/api/isu/:jia_isu_uuid/icon", getIsuIcon)
	e.GET("/api/isu/:jia_isu_uuid/graph", getIsuGraph)
	e.GET("/api/condition/:jia_isu_uuid", getIsuConditions)
	e.GET("/api/trend", getTrend)

	e.POST("/api/condition/:jia_isu_uuid", postIsuCondition)

	e.GET("/", getIndex)
	e.GET("/isu/:jia_isu_uuid", getIndex)
	e.GET("/isu/:jia_isu_uuid/condition", getIndex)
	e.GET("/isu/:jia_isu_uuid/graph", getIndex)
	e.GET("/register", getIndex)
	e.Static("/assets", frontendContentsPath+"/assets")

	mySQLConnectionData = NewMySQLConnectionEnv()

	mysqlConfig := mysql.NewConfig()
	mysqlConfig.Addr = mySQLConnectionData.Host + ":" + mySQLConnectionData.Port
	mysqlConfig.Passwd = mySQLConnectionData.Password
	mysqlConfig.DBName = mySQLConnectionData.DBName
	mysqlConfig.User = mySQLConnectionData.User
	jst, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		e.Logger.Fatalf("failed to set jst: %v", err)
		return
	}
	mysqlConfig.Loc = jst

	db, err = isuutil.NewIsuconDB(mysqlConfig)
	if err != nil {
		e.Logger.Fatalf("failed to connect db: %v", err)
		return
	}
	db.SetMaxOpenConns(100)
	defer db.Close()

	postIsuConditionTargetBaseURL = os.Getenv("POST_ISUCONDITION_TARGET_BASE_URL")
	if postIsuConditionTargetBaseURL == "" {
		e.Logger.Fatalf("missing: POST_ISUCONDITION_TARGET_BASE_URL")
		return
	}

	err = initCache()
	if err != nil {
		e.Logger.Fatalf("failed to init cache: %v", err)
		return
	}
	serverPort := fmt.Sprintf(":%v", getEnv("SERVER_APP_PORT", "3000"))
	e.Logger.Fatal(e.Start(serverPort))
}

func getSession(r *http.Request) (*sessions.Session, error) {
	session, err := sessionStore.Get(r, sessionName)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func getUserIDFromSession(c echo.Context) (string, int, error) {
	session, err := getSession(c.Request())
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("failed to get session: %v", err)
	}
	_jiaUserID, ok := session.Values["jia_user_id"]
	if !ok {
		return "", http.StatusUnauthorized, fmt.Errorf("no session")
	}

	jiaUserID := _jiaUserID.(string)
	_, ok = userCache.Load(jiaUserID)

	if !ok {
		c.Logger().Errorf("not found: user %s", jiaUserID)
		return "", http.StatusUnauthorized, fmt.Errorf("not found: user")
	}

	return jiaUserID, 0, nil
}

func getJIAServiceURL() string {
	return JIAServiceURL
}

func dbInitialize() error {
	// sqls := []string{
	// 	"DELETE FROM users WHERE id > 1000",
	// 	"DELETE FROM posts WHERE id > 10000",
	// 	"DELETE FROM comments WHERE id > 100000",
	// 	"UPDATE users SET del_flg = 0",
	// 	"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	// }

	// for _, sql := range sqls {
	// 	db.Exec(sql)
	// }

	indexsqls := []string{
		"CREATE INDEX uuid_time_idx ON isu_condition (jia_isu_uuid, timestamp DESC);",
	}
	for _, sql := range indexsqls {
		if err := isuutil.CreateIndexIfNotExists(db, sql); err != nil {
			return err
		}
	}
	return nil
}

// POST /initialize
// サービスを初期化
func postInitialize(c echo.Context) error {
	ctx := c.Request().Context()
	var request InitializeRequest
	err := c.Bind(&request)
	if err != nil {
		return c.String(http.StatusBadRequest, "bad request body")
	}

	cmd := exec.Command("../sql/init.sh")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	err = cmd.Run()
	if err != nil {
		c.Logger().Errorf("exec init.sh error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	_, err = db.Exec(
		"INSERT INTO `isu_association_config` (`name`, `url`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `url` = VALUES(`url`)",
		"jia_service_url",
		request.JIAServiceURL,
	)

	if err != nil {
		c.Logger().Errorf("db error : %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	if err := dbInitialize(); err != nil {
		c.Logger().Errorf("db error : %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	//columnの追加
	_, err = db.Exec("ALTER TABLE isu_condition ADD condition_level VARCHAR(255) DEFAULT ''")
	if err != nil {
		c.Logger().Errorf("db error : %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	var conditionList []IsuCondition
	err = db.Select(&conditionList, "SELECT * FROM isu_condition")
	for _, condition := range conditionList {
		var level string
		level, err = calculateConditionLevel(ctx, condition.Condition)
		if err != nil {
			c.Logger().Errorf("condition calculation error: %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		_, err = db.Exec("UPDATE isu_condition SET condition_level = ? WHERE id = ?", level, condition.ID)
		if err != nil {
			c.Logger().Errorf("db error : %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	//icon関連
	os.RemoveAll(iconDir)
	os.MkdirAll(iconDir, 0755)
	isuList := make([]Isu, 0)
	if err = db.Select(&isuList, "SELECT * FROM `isu`"); err != nil {
		c.Logger().Errorf("db error : %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	for _, isu := range isuList {
		iconPath := fmt.Sprintf("%s/%s.jpg", iconDir, isu.JIAIsuUUID)
		if err := os.WriteFile(iconPath, isu.Image, 0644); err != nil {
			c.Logger().Errorf("file error : %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	err = initCache()
	if err != nil {
		c.Logger().Errorf("cache error : %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	//測定スタート
	go func() {
		if _, err := http.Get("http://isucon-o11y:9000/api/group/collect"); err != nil {
			log.Printf("failed to communicate with pprotein: %v", err)
		}
	}()

	return c.JSON(http.StatusOK, InitializeResponse{
		Language: "go",
	})
}

// POST /api/auth
// サインアップ・サインイン
func postAuthentication(c echo.Context) error {
	ctx := c.Request().Context()

	reqJwt := strings.TrimPrefix(c.Request().Header.Get("Authorization"), "Bearer ")

	token, err := jwt.Parse(reqJwt, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, jwt.NewValidationError(fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]), jwt.ValidationErrorSignatureInvalid)
		}
		return jiaJWTSigningKey, nil
	})
	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError:
			return c.String(http.StatusForbidden, "forbidden")
		default:
			c.Logger().Error(err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.Logger().Errorf("invalid JWT payload")
		return c.NoContent(http.StatusInternalServerError)
	}
	jiaUserIDVar, ok := claims["jia_user_id"]
	if !ok {
		return c.String(http.StatusBadRequest, "invalid JWT payload")
	}
	jiaUserID, ok := jiaUserIDVar.(string)
	if !ok {
		return c.String(http.StatusBadRequest, "invalid JWT payload")
	}

	_, err = db.ExecContext(ctx, "INSERT IGNORE INTO user (`jia_user_id`) VALUES (?)", jiaUserID)
	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	userCache.Store(jiaUserID, User{})

	session, err := getSession(c.Request())
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	session.Values["jia_user_id"] = jiaUserID
	err = session.Save(c.Request(), c.Response())
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

// POST /api/signout
// サインアウト
func postSignout(c echo.Context) error {

	_, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	session, err := getSession(c.Request())
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	session.Options = &sessions.Options{MaxAge: -1, Path: "/"}
	err = session.Save(c.Request(), c.Response())
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

// GET /api/user/me
// サインインしている自分自身の情報を取得
func getMe(c echo.Context) error {

	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	res := GetMeResponse{JIAUserID: jiaUserID}
	return c.JSON(http.StatusOK, res)
}

// GET /api/isu
// ISUの一覧を取得
func getIsuList(c echo.Context) error {
	ctx := c.Request().Context()
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	defer tx.Rollback()

	isuList := []Isu{}
	err = tx.SelectContext(ctx,
		&isuList,
		"SELECT * FROM `isu` WHERE `jia_user_id` = ? ORDER BY `id` DESC",
		jiaUserID)
	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	responseList := []GetIsuListResponse{}
	for _, isu := range isuList {
		foundLastCondition := true

		// var lastCondition IsuCondition
		// err = tx.GetContext(ctx, &lastCondition, "SELECT * FROM `isu_condition` WHERE `jia_isu_uuid` = ? ORDER BY `timestamp` DESC LIMIT 1",
		// 	isu.JIAIsuUUID)

		lastCondition, err := getLatestCondition(ctx, isu.JIAIsuUUID)

		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				foundLastCondition = false
			} else {
				c.Logger().Errorf("db error: %v", err)
				return c.NoContent(http.StatusInternalServerError)
			}
		}

		var formattedCondition *GetIsuConditionResponse
		if foundLastCondition {
			conditionLevel, err := calculateConditionLevel(ctx, lastCondition.Condition)
			if err != nil {
				c.Logger().Error(err)
				return c.NoContent(http.StatusInternalServerError)
			}

			formattedCondition = &GetIsuConditionResponse{
				JIAIsuUUID:     lastCondition.JIAIsuUUID,
				IsuName:        isu.Name,
				Timestamp:      lastCondition.Timestamp.Unix(),
				IsSitting:      lastCondition.IsSitting,
				Condition:      lastCondition.Condition,
				ConditionLevel: conditionLevel,
				Message:        lastCondition.Message,
			}
		}

		res := GetIsuListResponse{
			ID:                 isu.ID,
			JIAIsuUUID:         isu.JIAIsuUUID,
			Name:               isu.Name,
			Character:          isu.Character,
			LatestIsuCondition: formattedCondition}
		responseList = append(responseList, res)
	}

	err = tx.Commit()
	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, responseList)
}

// POST /api/isu
// ISUを登録
func postIsu(c echo.Context) error {
	ctx := c.Request().Context()

	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	useDefaultImage := false

	jiaIsuUUID := c.FormValue("jia_isu_uuid")
	isuName := c.FormValue("isu_name")
	fh, err := c.FormFile("image")
	if err != nil {
		if !errors.Is(err, http.ErrMissingFile) {
			return c.String(http.StatusBadRequest, "bad format: icon")
		}
		useDefaultImage = true
	}

	var image []byte

	if useDefaultImage {
		image, err = ioutil.ReadFile(defaultIconFilePath)
		if err != nil {
			c.Logger().Error(err)
			return c.NoContent(http.StatusInternalServerError)
		}
	} else {
		file, err := fh.Open()
		if err != nil {
			c.Logger().Error(err)
			return c.NoContent(http.StatusInternalServerError)
		}
		defer file.Close()

		image, err = ioutil.ReadAll(file)
		if err != nil {
			c.Logger().Error(err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	_, err = getIsu(ctx, jiaIsuUUID)
	if err == nil {
		return c.String(http.StatusConflict, "duplicated: isu")
	}

	//isuのjiaへの登録
	targetURL := getJIAServiceURL() + "/api/activate"
	body := JIAServiceRequest{postIsuConditionTargetBaseURL, jiaIsuUUID}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	reqJIA, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewBuffer(bodyJSON))
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	reqJIA.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(reqJIA)
	if err != nil {
		c.Logger().Errorf("failed to request to JIAService: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	defer res.Body.Close()

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	if res.StatusCode != http.StatusAccepted {
		c.Logger().Errorf("JIAService returned error: status code %v, message: %v", res.StatusCode, string(resBody))
		return c.String(res.StatusCode, "JIAService returned error")
	}

	var isuFromJIA IsuFromJIA
	err = json.Unmarshal(resBody, &isuFromJIA)
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	timestamp := time.Now()
	isu := Isu{
		ID:         0,
		JIAIsuUUID: jiaIsuUUID,
		Name:       isuName,
		Image:      make([]byte, 0),
		JIAUserID:  jiaUserID,
		Character:  isuFromJIA.Character,
		CreatedAt:  timestamp,
		UpdatedAt:  timestamp,
	}
	query := "INSERT INTO `isu` (`jia_isu_uuid`, `name`, `image`, `character`, `jia_user_id`, `created_at`, `updated_at`)" +
		"VALUES (:jia_isu_uuid, :name, :image, :character, :jia_user_id, :created_at, :updated_at)"
	result, err := db.NamedExecContext(ctx, query, isu)

	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	id, err := result.LastInsertId()
	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	isu.ID = int(id)

	isuCache.Store(isu.JIAIsuUUID, isu)

	iconPath := fmt.Sprintf("%s/%s.jpg", iconDir, isu.JIAIsuUUID)
	if err := os.WriteFile(iconPath, image, 0644); err != nil {
		c.Logger().Errorf("file error : %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	time.Sleep(time.Millisecond * 500)

	return c.JSON(http.StatusCreated, isu)
}

func getIsu(ctx context.Context, uuid string) (Isu, error) {
	pc := make([]uintptr, 1)
	runtime.Callers(0, pc)
	function := runtime.FuncForPC(pc[0])
	ctx, span := otel.GetTracerProvider().Tracer("").Start(ctx, function.Name())
	defer span.End()
	isu, ok := isuCache.Load(uuid)
	if ok {
		return isu.(Isu), nil
	}
	return Isu{}, sql.ErrNoRows

}

// GET /api/isu/:jia_isu_uuid
// ISUの情報を取得
func getIsuID(c echo.Context) error {
	ctx := c.Request().Context()
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	jiaIsuUUID := c.Param("jia_isu_uuid")

	res, err := getIsu(ctx, jiaIsuUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.String(http.StatusNotFound, "not found: isu")
		}

		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	if res.JIAUserID != jiaUserID {
		return c.String(http.StatusNotFound, "not found: isu")
	}

	return c.JSON(http.StatusOK, res)
}

// GET /api/isu/:jia_isu_uuid/icon
// ISUのアイコンを取得
func getIsuIcon(c echo.Context) error {
	ctx := c.Request().Context()
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	jiaIsuUUID := c.Param("jia_isu_uuid")

	isu, err := getIsu(ctx, jiaIsuUUID)
	if errors.Is(err, sql.ErrNoRows) || isu.JIAUserID != jiaUserID {
		return c.String(http.StatusNotFound, "not found: isu")
	}
	header := c.Response().Header()
	header.Set(echo.HeaderContentType, "image/jpeg")
	header.Set("X-Accel-Redirect", fmt.Sprintf("/home/isucon/webapp/public/icon/%s.jpg", jiaIsuUUID))

	return c.NoContent(http.StatusOK)
}

// GET /api/isu/:jia_isu_uuid/graph
// ISUのコンディショングラフ描画のための情報を取得
func getIsuGraph(c echo.Context) error {
	ctx := c.Request().Context()
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	jiaIsuUUID := c.Param("jia_isu_uuid")
	datetimeStr := c.QueryParam("datetime")
	if datetimeStr == "" {
		c.Logger().Errorf("missing: datetime")
		return c.String(http.StatusBadRequest, "missing: datetime")
	}
	datetimeInt64, err := strconv.ParseInt(datetimeStr, 10, 64)
	if err != nil {
		c.Logger().Errorf("bad format: datetime: %s", datetimeStr)
		return c.String(http.StatusBadRequest, "bad format: datetime")
	}
	date := time.Unix(datetimeInt64, 0).Truncate(time.Hour)

	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	defer tx.Rollback()

	var count int
	err = tx.GetContext(ctx, &count, "SELECT COUNT(*) FROM `isu` WHERE `jia_user_id` = ? AND `jia_isu_uuid` = ?",
		jiaUserID, jiaIsuUUID)
	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	if count == 0 {
		return c.String(http.StatusNotFound, "not found: isu")
	}

	res, err := generateIsuGraphResponse(ctx, tx, jiaIsuUUID, date)
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	err = tx.Commit()
	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, res)
}

// グラフのデータ点を一日分生成
func generateIsuGraphResponse(ctx context.Context, tx *sqlx.Tx, jiaIsuUUID string, graphDate time.Time) ([]GraphResponse, error) {
	dataPoints := []GraphDataPointWithInfo{}
	conditionsInThisHour := []IsuCondition{}
	timestampsInThisHour := []int64{}
	var startTimeInThisHour time.Time
	var condition IsuCondition

	endTime := graphDate.Add(time.Hour * 24)

	query := "SELECT * FROM `isu_condition` WHERE `jia_isu_uuid` = ? AND ? <= `timestamp` AND `timestamp`< ? ORDER BY `timestamp` ASC"
	rows, err := tx.QueryxContext(ctx, query, jiaIsuUUID, graphDate, endTime)
	if err != nil {
		return nil, fmt.Errorf("db error: %v", err)
	}

	for rows.Next() {
		err = rows.StructScan(&condition)
		if err != nil {
			return nil, err
		}

		truncatedConditionTime := condition.Timestamp.Truncate(time.Hour)
		if truncatedConditionTime != startTimeInThisHour {
			if len(conditionsInThisHour) > 0 {
				data, err := calculateGraphDataPoint(conditionsInThisHour)
				if err != nil {
					return nil, err
				}

				dataPoints = append(dataPoints,
					GraphDataPointWithInfo{
						JIAIsuUUID:          jiaIsuUUID,
						StartAt:             startTimeInThisHour,
						Data:                data,
						ConditionTimestamps: timestampsInThisHour})
			}

			startTimeInThisHour = truncatedConditionTime
			conditionsInThisHour = []IsuCondition{}
			timestampsInThisHour = []int64{}
		}
		conditionsInThisHour = append(conditionsInThisHour, condition)
		timestampsInThisHour = append(timestampsInThisHour, condition.Timestamp.Unix())
	}

	if len(conditionsInThisHour) > 0 {
		data, err := calculateGraphDataPoint(conditionsInThisHour)
		if err != nil {
			return nil, err
		}

		dataPoints = append(dataPoints,
			GraphDataPointWithInfo{
				JIAIsuUUID:          jiaIsuUUID,
				StartAt:             startTimeInThisHour,
				Data:                data,
				ConditionTimestamps: timestampsInThisHour})
	}

	startIndex := len(dataPoints)
	endNextIndex := len(dataPoints)
	for i, graph := range dataPoints {
		if startIndex == len(dataPoints) && !graph.StartAt.Before(graphDate) {
			startIndex = i
		}
		if endNextIndex == len(dataPoints) && graph.StartAt.After(endTime) {
			endNextIndex = i
		}
	}

	filteredDataPoints := []GraphDataPointWithInfo{}
	if startIndex < endNextIndex {
		filteredDataPoints = dataPoints[startIndex:endNextIndex]
	}

	responseList := []GraphResponse{}
	index := 0
	thisTime := graphDate

	for thisTime.Before(graphDate.Add(time.Hour * 24)) {
		var data *GraphDataPoint
		timestamps := []int64{}

		if index < len(filteredDataPoints) {
			dataWithInfo := filteredDataPoints[index]

			if dataWithInfo.StartAt.Equal(thisTime) {
				data = &dataWithInfo.Data
				timestamps = dataWithInfo.ConditionTimestamps
				index++
			}
		}

		resp := GraphResponse{
			StartAt:             thisTime.Unix(),
			EndAt:               thisTime.Add(time.Hour).Unix(),
			Data:                data,
			ConditionTimestamps: timestamps,
		}
		responseList = append(responseList, resp)

		thisTime = thisTime.Add(time.Hour)
	}

	return responseList, nil
}

// 複数のISUのコンディションからグラフの一つのデータ点を計算
func calculateGraphDataPoint(isuConditions []IsuCondition) (GraphDataPoint, error) {
	conditionsCount := map[string]int{"is_broken": 0, "is_dirty": 0, "is_overweight": 0}
	rawScore := 0
	for _, condition := range isuConditions {
		badConditionsCount := 0

		if !isValidConditionFormat(condition.Condition) {
			return GraphDataPoint{}, fmt.Errorf("invalid condition format")
		}

		for _, condStr := range strings.Split(condition.Condition, ",") {
			keyValue := strings.Split(condStr, "=")

			conditionName := keyValue[0]
			if keyValue[1] == "true" {
				conditionsCount[conditionName] += 1
				badConditionsCount++
			}
		}

		if badConditionsCount >= 3 {
			rawScore += scoreConditionLevelCritical
		} else if badConditionsCount >= 1 {
			rawScore += scoreConditionLevelWarning
		} else {
			rawScore += scoreConditionLevelInfo
		}
	}

	sittingCount := 0
	for _, condition := range isuConditions {
		if condition.IsSitting {
			sittingCount++
		}
	}

	isuConditionsLength := len(isuConditions)

	score := rawScore * 100 / 3 / isuConditionsLength

	sittingPercentage := sittingCount * 100 / isuConditionsLength
	isBrokenPercentage := conditionsCount["is_broken"] * 100 / isuConditionsLength
	isOverweightPercentage := conditionsCount["is_overweight"] * 100 / isuConditionsLength
	isDirtyPercentage := conditionsCount["is_dirty"] * 100 / isuConditionsLength

	dataPoint := GraphDataPoint{
		Score: score,
		Percentage: ConditionsPercentage{
			Sitting:      sittingPercentage,
			IsBroken:     isBrokenPercentage,
			IsOverweight: isOverweightPercentage,
			IsDirty:      isDirtyPercentage,
		},
	}
	return dataPoint, nil
}

// GET /api/condition/:jia_isu_uuid
// ISUのコンディションを取得
func getIsuConditions(c echo.Context) error {
	ctx := c.Request().Context()

	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		c.Logger().Error(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	jiaIsuUUID := c.Param("jia_isu_uuid")
	if jiaIsuUUID == "" {
		c.Logger().Errorf("missing: jia_isu_uuid")
		return c.String(http.StatusBadRequest, "missing: jia_isu_uuid")
	}

	endTimeInt64, err := strconv.ParseInt(c.QueryParam("end_time"), 10, 64)
	if err != nil {
		c.Logger().Errorf("bad format: end_time : %s", c.QueryParam("end_time"))
		return c.String(http.StatusBadRequest, "bad format: end_time")
	}
	endTime := time.Unix(endTimeInt64, 0)
	conditionLevelCSV := c.QueryParam("condition_level")
	if conditionLevelCSV == "" {
		c.Logger().Errorf("missing: condition_level")
		return c.String(http.StatusBadRequest, "missing: condition_level")
	}
	conditionLevel := map[string]interface{}{}
	for _, level := range strings.Split(conditionLevelCSV, ",") {
		conditionLevel[level] = struct{}{}
	}

	startTimeStr := c.QueryParam("start_time")
	var startTime time.Time
	if startTimeStr != "" {
		startTimeInt64, err := strconv.ParseInt(startTimeStr, 10, 64)
		if err != nil {
			c.Logger().Errorf("bad format: start_time: %s", startTimeStr)
			return c.String(http.StatusBadRequest, "bad format: start_time")
		}
		startTime = time.Unix(startTimeInt64, 0)
	}

	var isuName string
	err = db.GetContext(ctx, &isuName,
		"SELECT name FROM `isu` WHERE `jia_isu_uuid` = ? AND `jia_user_id` = ?",
		jiaIsuUUID, jiaUserID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.String(http.StatusNotFound, "not found: isu")
		}

		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	conditionsResponse, err := getIsuConditionsFromDB(db, jiaIsuUUID, endTime, conditionLevelCSV, startTime, conditionLimit, isuName)
	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.JSON(http.StatusOK, conditionsResponse)
}

// ISUのコンディションをDBから取得
func getIsuConditionsFromDB(db *sqlx.DB, jiaIsuUUID string, endTime time.Time, conditionLevelCSV string, startTime time.Time,
	limit int, isuName string) ([]*GetIsuConditionResponse, error) {

	conditions := []IsuCondition{}
	var err error

	if startTime.IsZero() {
		err = db.Select(&conditions,
			"SELECT * FROM `isu_condition` WHERE `jia_isu_uuid` = ? AND ? like CONCAT('%', `condition_level`, '%')"+
				"	AND `timestamp` < ?"+
				"	ORDER BY `timestamp` DESC LIMIT ?",
			jiaIsuUUID, conditionLevelCSV, endTime, limit,
		)
	} else {
		err = db.Select(&conditions,
			"SELECT * FROM `isu_condition` WHERE `jia_isu_uuid` = ? AND ? like CONCAT('%', `condition_level`, '%')"+
				"	AND `timestamp` < ?"+
				"	AND ? <= `timestamp`"+
				"	ORDER BY `timestamp` DESC LIMIT ?",
			jiaIsuUUID, conditionLevelCSV, endTime, startTime, limit,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("db error: %v", err)
	}

	conditionsResponse := []*GetIsuConditionResponse{}
	for _, c := range conditions {
		data := GetIsuConditionResponse{
			JIAIsuUUID:     c.JIAIsuUUID,
			IsuName:        isuName,
			Timestamp:      c.Timestamp.Unix(),
			IsSitting:      c.IsSitting,
			Condition:      c.Condition,
			ConditionLevel: c.ConditionLevel,
			Message:        c.Message,
		}
		conditionsResponse = append(conditionsResponse, &data)

	}

	return conditionsResponse, nil
}

// ISUのコンディションの文字列からコンディションレベルを計算
func calculateConditionLevel(ctx context.Context, condition string) (string, error) {
	pc := make([]uintptr, 1)
	runtime.Callers(0, pc)
	function := runtime.FuncForPC(pc[0])
	ctx, span := otel.GetTracerProvider().Tracer("").Start(ctx, function.Name())
	defer span.End()
	var conditionLevel string

	warnCount := strings.Count(condition, "=true")
	switch warnCount {
	case 0:
		conditionLevel = conditionLevelInfo
	case 1, 2:
		conditionLevel = conditionLevelWarning
	case 3:
		conditionLevel = conditionLevelCritical
	default:
		return "", fmt.Errorf("unexpected warn count")
	}

	return conditionLevel, nil
}
func calculateConditionLevelInternal(condition string) (string, error) {
	var conditionLevel string

	warnCount := strings.Count(condition, "=true")
	switch warnCount {
	case 0:
		conditionLevel = conditionLevelInfo
	case 1, 2:
		conditionLevel = conditionLevelWarning
	case 3:
		conditionLevel = conditionLevelCritical
	default:
		return "", fmt.Errorf("unexpected warn count")
	}

	return conditionLevel, nil
}

func getLatestCondition(ctx context.Context, uuid string) (IsuCondition, error) {
	pc := make([]uintptr, 1)
	runtime.Callers(0, pc)
	function := runtime.FuncForPC(pc[0])
	ctx, span := otel.GetTracerProvider().Tracer("").Start(ctx, function.Name())
	defer span.End()

	condition, ok := conditionCache.Load(uuid)
	if ok {
		return condition.(IsuCondition), nil
	}

	var lastCondition IsuCondition
	err := db.Get(&lastCondition, "SELECT * FROM `isu_condition` WHERE `jia_isu_uuid` = ? ORDER BY `timestamp` DESC LIMIT 1",
		uuid)

	if err != nil {
		return IsuCondition{}, sql.ErrNoRows
	}
	conditionCache.Store(uuid, lastCondition)
	return lastCondition, nil
}
func getLatestConditionInternal(uuid string) (IsuCondition, error) {
	condition, ok := conditionCache.Load(uuid)
	if ok {
		return condition.(IsuCondition), nil
	}

	var lastCondition IsuCondition
	err := db.Get(&lastCondition, "SELECT * FROM `isu_condition` WHERE `jia_isu_uuid` = ? ORDER BY `timestamp` DESC LIMIT 1",
		uuid)

	if err != nil {
		return IsuCondition{}, sql.ErrNoRows
	}
	conditionCache.Store(uuid, lastCondition)
	return lastCondition, nil
}

type Group struct {
	mu sync.Mutex
	m  map[int64][]TrendResponse
}

var g = Group{}

func calcTrend() ([]TrendResponse, error) {
	key := time.Now().Unix()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.m == nil {
		g.m = make(map[int64][]TrendResponse)
	}

	if item, ok := g.m[key]; ok {
		return item, nil
	}

	fmt.Printf("calcTrend key: %d\n", key)
	res := make([]TrendResponse, 0)

	characterInfoIsuConditions := make(map[string][]*TrendCondition)
	characterWarningIsuConditions := make(map[string][]*TrendCondition)
	characterCriticalIsuConditions := make(map[string][]*TrendCondition)
	characterSet := make(map[string]struct{})

	is_invalid := false
	isuCache.Range(func(key interface{}, value interface{}) bool {

		isu := value.(Isu)
		character := isu.Character
		isuLastCondition, err := getLatestConditionInternal(isu.JIAIsuUUID)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				is_invalid = true
				return false
			}
		}

		if err == nil {
			conditionLevel, err := calculateConditionLevelInternal(isuLastCondition.Condition)
			if err != nil {
				is_invalid = true
				return false
			}
			trendCondition := TrendCondition{
				ID:        isu.ID,
				Timestamp: isuLastCondition.Timestamp.Unix(),
			}
			switch conditionLevel {
			case "info":
				characterInfoIsuConditions[character] = append(characterInfoIsuConditions[character], &trendCondition)
			case "warning":
				characterWarningIsuConditions[character] = append(characterWarningIsuConditions[character], &trendCondition)
			case "critical":
				characterCriticalIsuConditions[character] = append(characterCriticalIsuConditions[character], &trendCondition)
			}
			characterSet[character] = struct{}{}
		}
		return true
	})
	if is_invalid {
		return make([]TrendResponse, 0), nil
	}

	for character := range maps.Keys(characterSet) {
		sort.Slice(characterInfoIsuConditions[character], func(i, j int) bool {
			return characterInfoIsuConditions[character][i].Timestamp > characterInfoIsuConditions[character][j].Timestamp
		})
		sort.Slice(characterWarningIsuConditions[character], func(i, j int) bool {
			return characterWarningIsuConditions[character][i].Timestamp > characterWarningIsuConditions[character][j].Timestamp
		})
		sort.Slice(characterCriticalIsuConditions[character], func(i, j int) bool {
			return characterCriticalIsuConditions[character][i].Timestamp > characterCriticalIsuConditions[character][j].Timestamp
		})
		res = append(res,
			TrendResponse{
				Character: character,
				Info:      characterInfoIsuConditions[character],
				Warning:   characterWarningIsuConditions[character],
				Critical:  characterCriticalIsuConditions[character],
			})
	}
	g.m[key] = res
	return res, nil
}

// GET /api/trend
// ISUの性格毎の最新のコンディション情報
func getTrend(c echo.Context) error {

	res, err := calcTrend()
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.JSON(http.StatusOK, res)
}

// POST /api/condition/:jia_isu_uuid
// ISUからのコンディションを受け取る
func postIsuCondition(c echo.Context) error {
	ctx := c.Request().Context()
	// TODO: 一定割合リクエストを落としてしのぐようにしたが、本来は全量さばけるようにすべき
	dropProbability := 0.9
	if rand.Float64() <= dropProbability {
		// c.Logger().Warnf("drop post isu condition request")
		return c.NoContent(http.StatusAccepted)
	}

	jiaIsuUUID := c.Param("jia_isu_uuid")
	if jiaIsuUUID == "" {
		return c.String(http.StatusBadRequest, "missing: jia_isu_uuid")
	}

	req := []PostIsuConditionRequest{}
	err := c.Bind(&req)
	if err != nil {
		return c.String(http.StatusBadRequest, "bad request body")
	} else if len(req) == 0 {
		return c.String(http.StatusBadRequest, "bad request body")
	}

	_, err = getIsu(ctx, jiaIsuUUID)
	if err != nil {
		return c.String(http.StatusNotFound, "not found: isu")
	}

	cond := req[len(req)-1]
	timestamp := time.Unix(cond.Timestamp, 0)
	if !isValidConditionFormat(cond.Condition) {
		return c.String(http.StatusBadRequest, "bad request body")
	}

	created_at := time.Now()
	level, err := calculateConditionLevel(ctx, cond.Condition)
	if err != nil {
		c.Logger().Errorf("condition calculation error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	_, err = db.ExecContext(ctx,
		"INSERT INTO `isu_condition`"+
			"	(`jia_isu_uuid`, `timestamp`, `is_sitting`, `condition`,`condition_level`, `message`,`created_at`)"+
			"	VALUES (?, ?, ?, ?, ?, ?, ?)",
		jiaIsuUUID, timestamp, cond.IsSitting, cond.Condition, level, cond.Message, created_at)
	if err != nil {
		c.Logger().Errorf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	conditionCache.Delete(jiaIsuUUID)

	return c.NoContent(http.StatusAccepted)
}

// ISUのコンディションの文字列がcsv形式になっているか検証
func isValidConditionFormat(conditionStr string) bool {

	keys := []string{"is_dirty=", "is_overweight=", "is_broken="}
	const valueTrue = "true"
	const valueFalse = "false"

	idxCondStr := 0

	for idxKeys, key := range keys {
		if !strings.HasPrefix(conditionStr[idxCondStr:], key) {
			return false
		}
		idxCondStr += len(key)

		if strings.HasPrefix(conditionStr[idxCondStr:], valueTrue) {
			idxCondStr += len(valueTrue)
		} else if strings.HasPrefix(conditionStr[idxCondStr:], valueFalse) {
			idxCondStr += len(valueFalse)
		} else {
			return false
		}

		if idxKeys < (len(keys) - 1) {
			if conditionStr[idxCondStr] != ',' {
				return false
			}
			idxCondStr++
		}
	}

	return (idxCondStr == len(conditionStr))
}

func getIndex(c echo.Context) error {
	return c.File(frontendContentsPath + "/index.html")
}
