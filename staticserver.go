package main

import (
	"crypto/subtle"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/astaxie/beego/logs"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
)

type home struct {
	Title string
}

type AppLogger struct {
	Daily      bool   `yaml:"Daily"`
	MaxDays    int64  `yaml:"MaxDays"`
	Rotate     bool   `yaml:"Rotate"`
	Level      int    `yaml:"Level"`
	Perm       string `yaml:"Perm"`
	RotatePerm string `yaml:"RotatePerm"`
	LogPath    string `yaml:"LogPath"`
}

type AppConfig struct {
	Logger      AppLogger
	ListenPort  string   `yaml:"listenPort"`
	TemplateDir string   `yaml:"templateDir"`
	StaticDir   string   `yaml:"staticDir"`
	UploadDir   string   `yaml:"uploadDir"`
	FileExtType []string `yaml:"fileExtType"`
	User        string   `yaml:"user"`
	Password    string   `yaml:"password"`
}

var logger = logs.NewLogger(10000)
var appConfig = AppConfig{}
var templateDir string
var uploadDir string
var staticDir string

func init() {

	// read config
	currentPath := getCurrPath()
	configFile := currentPath + "/config.yaml"
	readData, err := ioutil.ReadFile(configFile)
	if err != nil {
		logger.Error("[config] read config file failed, %v", err)
		os.Exit(0)
	}

	err = yaml.Unmarshal(readData, &appConfig)
	if err != nil {
		logger.Error("[config] parse config.yaml failed, %v", err)
		os.Exit(0)
	}

	loggerConfig := appConfig.Logger
	logPath := currentPath + "/" + loggerConfig.LogPath
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		logger.Error("[config] create log dir failed, %v", err)
		os.Exit(0)
	}

	templateDir = filepath.FromSlash(currentPath + "/" + appConfig.TemplateDir)
	staticDir = filepath.FromSlash(currentPath + "/" + appConfig.StaticDir)

	uploadDir = filepath.Clean(appConfig.UploadDir)
	if !filepath.IsAbs(uploadDir) {
		uploadDir, _ = filepath.Abs(uploadDir)
	}
	if uploadDir[len(uploadDir)-1] != '/' {
		uploadDir += "/"
	}
	uploadDir = filepath.FromSlash(uploadDir)

	// logger config
	loggerConfigJson := `{"filename":"%v", "daily": %v, "maxDays": %v, "rotate": %v, "level": %v, "perm":"%v", "rotateperm":"%v"}`
	loggerJsonConfig := fmt.Sprintf(loggerConfigJson, logPath, loggerConfig.Daily, loggerConfig.MaxDays,
		loggerConfig.Rotate, loggerConfig.Level, loggerConfig.Perm, loggerConfig.RotatePerm)

	logger.SetLogger("file", loggerJsonConfig)
	logger.EnableFuncCallDepth(true)
	logger.SetLogFuncCallDepth(2)
	logger.SetLogger("console", fmt.Sprintf(`{"level": %d}`, logs.LevelInformational))

	logger.Info("[init] load config file: %s", configFile)
	logger.Info("[init] use log path: %s", logPath)
	logger.Info("[init] template path: %s", templateDir)
	logger.Info("[init] static path: %s", staticDir)
	logger.Info("[init] upload path: %s", uploadDir)
}

func main() {

	topRouter := mux.NewRouter().StrictSlash(true)

	topRouter.HandleFunc("/", index)

	topRouter.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	topRouter.HandleFunc("/upload", upload)

	topRouter.PathPrefix("/file").Handler(http.HandlerFunc(file))

	topRouter.NotFoundHandler = http.HandlerFunc(notFound)

	username := appConfig.User
	password := appConfig.Password

	n := negroni.New()
	n.Use(negroni.HandlerFunc(func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		if BasicAuth(w, r, username, password, "Provide user name and password") {
			/* Call the next handler iff Basic-Auth succeeded */
			logger.Info("ping, %s, %s", r.RequestURI, time.Now().Format("2006-01-02 15:04:05.999999999"))

			next(w, r)
		}
	}))

	n.UseHandler(topRouter)

	http.ListenAndServe(":"+appConfig.ListenPort, n)
}

func notFound(w http.ResponseWriter, r *http.Request) {

	http.StripPrefix("/", http.FileServer(http.Dir(uploadDir))).ServeHTTP(w, r)
}

func index(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != "/" {
		http.Error(w, "Not found", 404)
		return
	}

	title := home{Title: "上传页"}

	templateFile := templateDir + "index.html"
	if _, err := os.Stat(templateFile); os.IsNotExist(err) {
		logger.Error("[Template] template not exist, %v", err)
		return
	}

	t, _ := template.ParseFiles(templateFile)
	t.Execute(w, title)
}

func upload(w http.ResponseWriter, r *http.Request) {

	if r.Method == "GET" {

		templateFile := templateDir + "file.html"
		if _, err := os.Stat(templateFile); os.IsNotExist(err) {
			logger.Error("[Template] template not exist, %v", err)
			return
		}

		t, _ := template.ParseFiles(templateFile)
		title := home{Title: "上传文件"}
		t.Execute(w, title)

	} else {
		r.ParseMultipartForm(32 << 20)

		file, handler, err := r.FormFile("uploadfile")
		if file == nil {
			fmt.Fprintf(w, "%v", "上传失败,文件为空")
			logger.Error("[Upload] upload failed, %v", err)
			return
		}

		if err != nil {
			fmt.Fprintf(w, "%v", "上传失败")
			logger.Error("[Upload] upload failed, %v", err)
			return
		}

		filename := handler.Filename
		fileext := filepath.Ext(filename)
		if !stringInSlice(fileext, appConfig.FileExtType) {
			fmt.Fprintf(w, "%v", "不允许的上传类型")
			return
		}

		f, _ := os.OpenFile(uploadDir+filename, os.O_CREATE|os.O_WRONLY, 0660)
		_, err = io.Copy(f, file)
		if err != nil {
			fmt.Fprintf(w, "%v", "上传失败")
			logger.Error("%v", err)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		fileLink := `<br/><a href="/file" target="_blank">查看文件</a><br/><a href="/" target="_blank">返回首页</a>`;
		fmt.Fprintf(w, "%s", filename+"上传完成"+fileLink)
	}
}

func file(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.Header().Set("Expires", "0")
	http.StripPrefix("/file", http.FileServer(http.Dir(uploadDir))).ServeHTTP(w, r)
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func getCurrPath() string {
	file, _ := exec.LookPath(os.Args[0])
	path, _ := filepath.Abs(file)
	index := strings.LastIndex(path, string(os.PathSeparator))
	ret := path[:index]
	return ret
}

func BasicAuth(w http.ResponseWriter, r *http.Request, username, password, realm string) bool {

	user, pass, ok := r.BasicAuth()

	if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 || !CheckPasswordHash(pass, password) {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
		w.WriteHeader(401)
		w.Write([]byte("Unauthorised.\n"))
		return false
	}

	return true
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	//bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}
