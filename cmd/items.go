// `lockr add|edit|rm|mv`: create and change items. Secret values and TOTP
// seeds are only ever read from a hidden prompt or stdin, never argv.
package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gtchakama/lockr/internal/model"
	"github.com/gtchakama/lockr/internal/totp"
	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

func parseItemRef(s string) (model.Ref, error) {
	r, err := model.ItemRef(s)
	return r, usageWrap(err)
}

func projectItems(u *vault.Unlocked, p model.Name) (map[model.Name]*model.Item, error) {
	items, ok := u.Body.Projects[p]
	if !ok {
		return nil, fmt.Errorf("project %q %w: create it with `lockr project new %s`", p, model.ErrNotFound, p)
	}
	return items, nil
}

func readTOTPSeed() (string, error) {
	if !stdinIsTTY() {
		return "", usageErr("--totp needs an interactive terminal to enter the seed")
	}
	b, err := readPassword("TOTP seed (base32): ")
	if err != nil {
		return "", err
	}
	seed := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(string(b)), " ", ""))
	if _, err := totp.DecodeSeed(seed); err != nil {
		return "", usageWrap(err)
	}
	return seed, nil
}

func parseEnvFlag(s string) (model.EnvName, error) {
	if s == "" {
		return "", nil
	}
	e, err := model.ParseEnvName(s)
	return e, usageWrap(err)
}

func newAddCmd() *cobra.Command {
	var kind, url, username, env string
	var withTOTP, fromStdin, replace bool
	c := &cobra.Command{
		Use:   "add <project>/<item>",
		Short: "Add an item (value is prompted, or read with --stdin)",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			ref, err := parseItemRef(args[0])
			if err != nil {
				return err
			}
			k, err := model.ParseKind(kind)
			if err != nil {
				return usageWrap(err)
			}
			envName, err := parseEnvFlag(env)
			if err != nil {
				return err
			}
			return withWrite(func(u *vault.Unlocked) error {
				items, err := projectItems(u, ref.Project)
				if err != nil {
					return err
				}
				old, exists := items[ref.Item]
				if exists && !replace {
					return fmt.Errorf("item %s already exists: pass --replace to overwrite", ref)
				}
				label := "Password"
				if k == model.KindSecret {
					label = "Secret value"
				}
				val, err := readSecretValue(label+": ", fromStdin)
				if err != nil {
					return err
				}
				it := &model.Item{Kind: k, URL: url, Username: username, Env: envName, Secret: val,
					CreatedAt: now().UTC(), UpdatedAt: now().UTC()}
				if exists {
					it.CreatedAt = old.CreatedAt
				}
				if withTOTP {
					if it.TOTPSeed, err = readTOTPSeed(); err != nil {
						return err
					}
				}
				items[ref.Item] = it
				fmt.Fprintf(stdout, "Saved %s\n", ref)
				return nil
			})
		},
	}
	f := c.Flags()
	f.StringVar(&kind, "kind", string(model.KindSecret), "login or secret")
	f.StringVar(&url, "url", "", "website URL")
	f.StringVar(&username, "username", "", "login username")
	f.StringVar(&env, "env", "", "environment variable name used by `lockr run`")
	f.BoolVar(&withTOTP, "totp", false, "prompt for a TOTP seed")
	f.BoolVar(&fromStdin, "stdin", false, "read the value from stdin")
	f.BoolVar(&replace, "replace", false, "overwrite an existing item")
	return c
}

func newEditCmd() *cobra.Command {
	var url, username, env string
	var secret, withTOTP, fromStdin bool
	c := &cobra.Command{
		Use:   "edit <project>/<item>",
		Short: "Change an item's metadata, secret or TOTP seed",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := parseItemRef(args[0])
			if err != nil {
				return err
			}
			envName, err := parseEnvFlag(env)
			if err != nil {
				return err
			}
			fl := cmd.Flags()
			return withWrite(func(u *vault.Unlocked) error {
				it, err := u.Body.Item(ref)
				if err != nil {
					return err
				}
				if fl.Changed("url") {
					it.URL = url
				}
				if fl.Changed("username") {
					it.Username = username
				}
				if fl.Changed("env") {
					it.Env = envName
				}
				if secret {
					v, err := readSecretValue("New value: ", fromStdin)
					if err != nil {
						return err
					}
					it.Secret = v
				}
				if withTOTP {
					if it.TOTPSeed, err = readTOTPSeed(); err != nil {
						return err
					}
				}
				it.UpdatedAt = now().UTC()
				fmt.Fprintf(stdout, "Updated %s\n", ref)
				return nil
			})
		},
	}
	f := c.Flags()
	f.StringVar(&url, "url", "", "website URL (empty clears)")
	f.StringVar(&username, "username", "", "username (empty clears)")
	f.StringVar(&env, "env", "", "env var name (empty clears)")
	f.BoolVar(&secret, "secret", false, "re-enter the secret value")
	f.BoolVar(&fromStdin, "stdin", false, "with --secret, read the value from stdin")
	f.BoolVar(&withTOTP, "totp", false, "re-enter the TOTP seed")
	return c
}

func newRmCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "rm <project>/<item>",
		Short: "Delete an item",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			ref, err := parseItemRef(args[0])
			if err != nil {
				return err
			}
			return withWrite(func(u *vault.Unlocked) error {
				if _, err := u.Body.Item(ref); err != nil {
					return err
				}
				if err := confirm(fmt.Sprintf("Delete %s?", ref), yes); err != nil {
					return err
				}
				delete(u.Body.Projects[ref.Project], ref.Item)
				fmt.Fprintf(stdout, "Deleted %s\n", ref)
				return nil
			})
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "skip the confirmation")
	return c
}

func newMvCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mv <from> <to>",
		Short: "Rename or move an item",
		Args:  usageArgs(cobra.ExactArgs(2)),
		RunE: func(_ *cobra.Command, args []string) error {
			from, err := parseItemRef(args[0])
			if err != nil {
				return err
			}
			to, err := parseItemRef(args[1])
			if err != nil {
				return err
			}
			return withWrite(func(u *vault.Unlocked) error {
				it, err := u.Body.Item(from)
				if err != nil {
					return err
				}
				dst, err := projectItems(u, to.Project)
				if err != nil {
					return err
				}
				if _, ok := dst[to.Item]; ok {
					return errors.New("destination " + to.String() + " already exists")
				}
				delete(u.Body.Projects[from.Project], from.Item)
				it.UpdatedAt = now().UTC()
				dst[to.Item] = it
				fmt.Fprintf(stdout, "Moved %s to %s\n", from, to)
				return nil
			})
		},
	}
}
