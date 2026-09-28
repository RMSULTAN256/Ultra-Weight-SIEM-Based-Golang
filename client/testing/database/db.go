package database

// import (
// 	"log"

// 	"gorm.io/driver/postgres"
// 	"gorm.io/gorm"

// 	"server1/config"
// )

// var DB *gorm.DB

// func Connect(cfg *config.Config) {
// 	var err error
// 	DB, err = gorm.Open(postgres.Open(cfg.DBUrl()), &gorm.Config{})
// 	if err != nil {
// 		log.Fatal("Failed to connect to database:", err)
// 	}

// 	sqlDB, _ := DB.DB()
// 	sqlDB.SetMaxIdleConns(10)
// 	sqlDB.SetMaxOpenConns(100)

// 	log.Println("Database connected successfully")
// }
