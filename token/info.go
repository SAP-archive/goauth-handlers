package token

type Info struct {
	UserID   string   `json:"user_id"`
	UserName string   `json:"user_name"`
	Scopes   []string `json:"scope"`
}
