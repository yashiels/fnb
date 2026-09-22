package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/yashiels/fnb/internal/secure"
)

const requiredIdentity = "view-only-secondary"

type File struct {
	Username          string   `toml:"username"`
	Identity          string   `toml:"identity"`
	CredentialCommand []string `toml:"credential_command"`
}

type Config struct {
	Dir               string
	Username          string
	Identity          string
	CredentialCommand []string
}

func Dir(override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "fnb"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".config", "fnb"), nil
}

func Resolve(override string) (*Config, error) {
	directory, err := Dir(override)
	if err != nil {
		return nil, err
	}
	root, err := OpenDir(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := load(root)
	if err != nil {
		return nil, err
	}
	username := file.Username
	if value := os.Getenv("FNB_USERNAME"); value != "" {
		username = value
	}
	if username == "" {
		return nil, errors.New("missing username: set FNB_USERNAME or username in config.toml")
	}
	if file.Identity != requiredIdentity {
		return nil, fmt.Errorf("identity must be exactly %q in config.toml", requiredIdentity)
	}
	return &Config{
		Dir:               directory,
		Username:          username,
		Identity:          file.Identity,
		CredentialCommand: append([]string(nil), file.CredentialCommand...),
	}, nil
}

func OpenDir(path string) (*os.Root, error) {
	info, err := os.Lstat(path)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("create config directory: %w", err)
		}
		created = true
		info, err = os.Lstat(path)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect config directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, &secure.UnsafeDirectoryError{Reason: "config directory is a symlink"}
	}
	if !info.IsDir() {
		return nil, &secure.UnsafeDirectoryError{Reason: "config path is not a directory"}
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open config directory: %w", err)
	}
	pinnedInfo, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("inspect pinned config directory: %w", err)
	}
	if !os.SameFile(info, pinnedInfo) {
		root.Close()
		return nil, &secure.UnsafeDirectoryError{Reason: "config directory changed while opening"}
	}
	if err := secure.CheckRoot(root); err != nil {
		root.Close()
		return nil, err
	}
	if created {
		if err := root.Chmod(".", 0o700); err != nil {
			root.Close()
			return nil, fmt.Errorf("secure config directory: %w", err)
		}
	}
	return root, nil
}

func (config *Config) Password() (string, error) {
	if password := os.Getenv("FNB_PASSWORD"); password != "" {
		return password, nil
	}
	if len(config.CredentialCommand) == 0 {
		return "", errors.New("missing password: set FNB_PASSWORD or credential_command in config.toml")
	}
	command, err := secure.Command(config.CredentialCommand)
	if err != nil {
		return "", err
	}
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("credential_command failed: %w", err)
	}
	password := strings.TrimSpace(string(output))
	if password == "" {
		return "", errors.New("credential_command returned an empty password")
	}
	return password, nil
}

func load(root *os.Root) (File, error) {
	info, err := root.Lstat("config.toml")
	if errors.Is(err, os.ErrNotExist) {
		return File{}, nil
	}
	if err != nil {
		return File{}, fmt.Errorf("inspect config.toml: %w", err)
	}
	if !info.Mode().IsRegular() {
		return File{}, errors.New("config.toml must be a regular file")
	}
	file, err := root.Open("config.toml")
	if err != nil {
		return File{}, fmt.Errorf("open config.toml: %w", err)
	}
	defer file.Close()
	var parsed File
	if _, err := toml.NewDecoder(file).Decode(&parsed); err != nil {
		return File{}, fmt.Errorf("parse config.toml: %w", err)
	}
	return parsed, nil
}
