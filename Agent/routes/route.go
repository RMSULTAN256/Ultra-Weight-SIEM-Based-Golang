package routes

import (
	"Agent/models"
	"bytes"
	"fmt"
	"net/http"

	"github.com/bytedance/sonic"
)

func SendHeartbeat(client *http.Client, url string, status *models.DeviceStatus) error {
	jsonData, err := sonic.Marshal(status)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server merespons error status: %d", resp.StatusCode)
	}

	return nil
}
