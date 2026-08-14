package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func GenerateSecret(length int) string {
	if length <= 0 {
		length = 20
	}
	b := make([]byte, length)
	_, _ = rand.Read(b)

	var out strings.Builder
	var buffer uint64
	var bits int
	for _, by := range b {
		buffer = (buffer << 8) | uint64(by)
		bits += 8
		for bits >= 5 {
			idx := (buffer >> (bits - 5)) & 31
			bits -= 5
			out.WriteByte(alphabet[idx])
		}
	}
	if bits > 0 {
		idx := (buffer << (5 - bits)) & 31
		out.WriteByte(alphabet[idx])
	}
	return out.String()
}

func decodeBase32(input string) []byte {
	input = strings.ToUpper(strings.TrimRight(input, "="))
	var out []byte
	var buffer uint64
	var bits int
	for _, ch := range input {
		idx := strings.IndexRune(alphabet, ch)
		if idx < 0 {
			continue
		}
		buffer = (buffer << 5) | uint64(idx)
		bits += 5
		if bits >= 8 {
			out = append(out, byte((buffer>>(bits-8))&0xff))
			bits -= 8
		}
	}
	return out
}

func hotp(secret string, counter uint64) string {
	key := decodeBase32(secret)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", code)
}

func GenerateTOTP(secret string, step int64) string {
	if step == 0 {
		step = time.Now().Unix() / 30
	}
	return hotp(secret, uint64(step))
}

func VerifyTOTP(secret, token string, window int) bool {
	if window <= 0 {
		window = 1
	}
	normalized := strings.ReplaceAll(token, " ", "")
	step := time.Now().Unix() / 30
	for i := -window; i <= window; i++ {
		if hotp(secret, uint64(step+int64(i))) == normalized {
			return true
		}
	}
	return false
}

func KeyURI(account, issuer, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}

func RandomRecoveryCodes(count int) []string {
	if count <= 0 {
		count = 8
	}
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		codes[i] = strings.ToUpper(base32.StdEncoding.EncodeToString(b)[:8])
	}
	return codes
}
