package lib

import (
	"encoding/json"
	"log"
	"os"
)

// EnsureJSONFileExists ensures the JSON file exists and is valid; if not, creates it with initial data.
func EnsureJSONFileExists(filePath string, initialData interface{}) error {
	// Check if the file exists and is not empty
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) || fileInfo.Size() == 0 {
		file, err := os.Create(filePath)
		if err != nil {
			return err
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "    ")
		if err := encoder.Encode(initialData); err != nil {
			return err
		}
	}
	return nil
}
func LoadFromJSON(filename string, data interface{}) {
	if err := EnsureJSONFileExists(filename, data); err != nil {
		log.Fatal(err)
	}

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(data); err != nil {
		log.Fatal(err)
	}
}

func SaveToJSON(filename string, data interface{}) {
	if err := EnsureJSONFileExists(filename, data); err != nil {
		log.Fatal(err)
	}

	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatal(err)
	}
}
