// `lockr get`: the agent-facing read path. Never prompts; refuses to print to
// a terminal without --reveal so values flow into $( ) or pipes, not a model.
package cmd

import (
	"errors"
	"fmt"

	"github.com/gtchakama/lockr/internal/model"
	"github.com/gtchakama/lockr/internal/totp"
	"github.com/spf13/cobra"
)

const ttyMsg = "refusing to print a secret to a terminal. Use it without seeing it: " +
	`cmd --token "$(lockr get <ref>)" or lockr get <ref> | cmd. ` +
	"Pass --reveal only if a human wants to see it"

func newGetCmd() *cobra.Command {
	var reveal bool
	c := &cobra.Command{
		Use:   "get <project>/<item>[.password|.username|.url|.totp]",
		Short: "Write a value to stdout (for $(...) and pipes)",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			ref, err := model.ParseRef(args[0])
			if err != nil {
				return usageWrap(err)
			}
			if stdoutIsTTY() && !reveal {
				return &exitError{code: codeTTY, err: errors.New(ttyMsg)}
			}
			u, path, err := openRead(false)
			if err != nil {
				return err
			}
			defer u.Close()
			it, err := u.Body.Item(ref)
			if err != nil {
				return err
			}
			var out []byte
			missing := func() error { return fmt.Errorf("%s: field %w", ref, model.ErrNotFound) }
			switch ref.Field {
			case model.FieldUsername:
				if it.Username == "" {
					return missing()
				}
				out = []byte(it.Username)
			case model.FieldURL:
				if it.URL == "" {
					return missing()
				}
				out = []byte(it.URL)
			case model.FieldTOTP:
				if it.TOTPSeed == "" {
					return missing()
				}
				code, err := totp.Code(it.TOTPSeed, now())
				if err != nil {
					return err
				}
				out = []byte(code)
			default:
				if len(it.Secret) == 0 {
					return missing()
				}
				out = it.Secret
			}
			recordAudit(path, "get", ref.String())
			_, err = stdout.Write(out)
			return err
		},
	}
	c.Flags().BoolVar(&reveal, "reveal", false, "allow printing to a terminal")
	return c
}
