# 项目名称
PROJECT_NAME := networking


# 可执行文件名称
BINARY := $(PROJECT_NAME).exe

# Go 包
GO_PACKAGES := golang.org/x/net

# 初始化 Go 模块
init:
	@echo "Initializing Go module..."
	go mod init $(PROJECT_NAME)

# 获取依赖包
deps:
	@echo "Getting dependencies..."
	go get $(GO_PACKAGES)

# 清理生成的文件
clean:
	@echo "Cleaning up..."
	go clean

# # 构建项目
# build: clean
# 	@echo "Building project..."
# 	go build -o $(BINARY) $(MAIN_FILE)

rule: clean
	@echo "Building rule"
	go build -o $(BINARY) clientRule.go rules.go colorfulLog.go
	./$(BINARY)


ruleHTTP: clean
	@echo "Building ruleHTTP"
	go build -o $(BINARY) clientRuleHTTP.go rules.go colorfulLog.go
	./$(BINARY)

rulePID: clean
	@echo "Building ruleProcess"
	go build -o $(BINARY) clientRuleProcess.go rules.go oscmd.go colorfulLog.go
	./$(BINARY)


# 运行项目
run:
	@echo "Running project..."
	./$(BINARY)

# 一键初始化、获取依赖并运行项目
all: init deps run

# 帮助信息
help:
	@echo "Usage:"
	@echo "  make init     - Initialize Go module"
	@echo "  make deps     - Get dependencies"
	@echo "  make clean    - Clean generated files"
	@echo "  make build    - Build the project"
	@echo "  make run      - Run the project"
	@echo "  make all      - Initialize, get dependencies, and run the project"
	@echo "  make help     - Show this help message"
