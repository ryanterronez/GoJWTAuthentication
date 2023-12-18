package initializers

import "GoJWTAuthentication/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
