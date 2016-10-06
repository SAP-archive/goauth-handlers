package cookie

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SAP/goauth_handlers/session"
	"github.com/SAP/gologger"
)

const sessionPrefix = "goauth-"

const year time.Duration = time.Hour * 24 * 365

// NewStore Creates new store
func NewStore(encryptor Encryptor, logger gologger.Logger) session.Store {
	return &store{
		encryptor: encryptor,
		logging:   logger,
	}
}

type store struct {
	encryptor Encryptor
	logging   gologger.Logger
}

func (s *store) Get(req *http.Request, name string) (session.Session, error) {
	cookies := getSessionCookiesWithName(req, name)

	values, err := s.readSessionValues(cookies)
	session := &cookieSession{
		name:               name,
		initialCookieCount: len(cookies),
		values:             values,
	}
	return session, err
}

func (s *store) readSessionValues(cookies []*http.Cookie) (map[string]string, error) {
	sessionValueString := ""
	for _, cookie := range cookies {
		if err := s.encryptor.Decrypt(cookie); err != nil {
			s.logging.Warnf("Failed to decrypt session cookie due to '%s'.", err)
			return nil, err
		}
		sessionValueString += cookie.Value
	}

	if len(sessionValueString) <= 0 {
		return nil, nil
	}

	values := make(map[string]string)
	if err := json.Unmarshal([]byte(sessionValueString), &values); err != nil {
		s.logging.Warnf("Failed to unmarshal session due to '%s'.", err)
		return nil, err
	}
	return values, nil
}

func getSessionCookiesWithName(req *http.Request, name string) []*http.Cookie {
	allSessionCookies := getSessionCookies(req)
	result := make([]*http.Cookie, 0)
	cookieIndex := 0
	for {
		cookieIndex++
		cookieName := getCookieName(name, cookieIndex)
		cookie, found := allSessionCookies[cookieName]
		if !found {
			break
		}
		result = append(result, cookie)
	}
	return result
}

func getSessionCookies(req *http.Request) map[string]*http.Cookie {
	result := make(map[string]*http.Cookie)
	for _, cookie := range req.Cookies() {
		if strings.HasPrefix(cookie.Name, sessionPrefix) {
			result[cookie.Name] = cookie
		}
	}
	return result
}

func (s *store) Save(resp http.ResponseWriter, session session.Session) error {
	if actualSession, ok := session.(*cookieSession); ok {
		if len(actualSession.values) > 0 {
			return s.writeSession(resp, actualSession)
		} else {
			return s.eraseSession(resp, actualSession)
		}
	} else {
		panic("Invalid session type!")
	}
}

func (s *store) writeSession(resp http.ResponseWriter, session *cookieSession) error {
	sessionValueString := session.valuesAsString()

	blocks := s.splitValueString(sessionValueString, MaxCookieValueSize)
	for i, block := range blocks {
		cookie := &http.Cookie{
			Name:     getCookieName(session.name, i+1),
			Value:    block,
			Path:     "/",
			HttpOnly: true,
		}
		if err := s.encryptor.Encrypt(cookie); err != nil {
			s.logging.Errorf("Failed to encrypt session due to '%s'.", err)
			return err
		}
		http.SetCookie(resp, cookie)
	}
	// footer cookie, in case of old session
	http.SetCookie(
		resp,
		getExpiryCookie(getCookieName(session.name, len(blocks)+1)),
	)
	return nil
}

func (s *store) splitValueString(value string, blockSize int) []string {
	result := make([]string, 0)
	for len(value) > 0 {
		block := value
		if len(block) > blockSize {
			block = value[:blockSize]
			value = value[blockSize:]
		} else {
			value = ""
		}
		result = append(result, block)
	}
	return result
}

func (s *store) eraseSession(resp http.ResponseWriter, session *cookieSession) error {
	for i := 1; i <= session.initialCookieCount; i++ {
		http.SetCookie(
			resp,
			getExpiryCookie(getCookieName(session.Name(), i)),
		)
	}
	return nil
}

func getCookieName(sessionName string, index int) string {
	return fmt.Sprintf("%s%s-%d", sessionPrefix, sessionName, index)
}

func getExpiryCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Now().Add(-year),
	}
}

type cookieSession struct {
	name               string
	initialCookieCount int
	values             map[string]string
}

func (s *cookieSession) valuesAsString() string {
	sessionValuesAsJSON, err := json.Marshal(s.values)
	if err != nil {
		// Should not happen
		panic(fmt.Sprintf("Failed to serialize values: %#v\n", s.values))
	}
	return string(sessionValuesAsJSON)
}

func (s *cookieSession) Name() string {
	return s.name
}

func (s *cookieSession) Values() map[string]string {
	if s.values == nil {
		s.values = make(map[string]string)
	}
	return s.values
}

func (s *cookieSession) Clear() {
	s.values = nil
}
