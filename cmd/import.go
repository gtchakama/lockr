// `lockr import-v1`: migrate a Lockr v1 vault into the v2 vault. Prints
// counts and names only, never values; never overwrites existing items.
package cmd

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/gtchakama/lockr/internal/crypto"
	"github.com/gtchakama/lockr/internal/legacy"
	"github.com/gtchakama/lockr/internal/model"
	"github.com/gtchakama/lockr/internal/vault"
	"github.com/spf13/cobra"
)

func newImportV1Cmd() *cobra.Command {
	var prefix string
	c := &cobra.Command{
		Use:   "import-v1 [path]",
		Short: "Import a Lockr v1 vault (default ~/.lockr/vault.enc)",
		Args:  usageArgs(cobra.MaximumNArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			src := "~/.lockr/vault.enc"
			if len(args) == 1 {
				src = args[0]
			}
			src, err := expandHome(src)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(src)
			if err != nil {
				return fmt.Errorf("reading v1 vault: %w", err)
			}
			if err := requireTTY("import-v1"); err != nil {
				return err
			}
			return withWrite(func(u *vault.Unlocked) error {
				pw, err := readPassword("v1 master password: ")
				if err != nil {
					return err
				}
				defer crypto.Zero(pw)
				groups, err := legacy.Decrypt(data, pw)
				if err != nil {
					return err
				}
				var created, imported, skipped int
				gnames := make([]string, 0, len(groups))
				for g := range groups {
					gnames = append(gnames, g)
				}
				slices.Sort(gnames)
				for _, g := range gnames {
					pname, err := model.ParseName(prefix + g)
					if err != nil {
						fmt.Fprintf(stderr, "lockr: warning: skipping group %q: %v\n", g, err)
						skipped += len(groups[g])
						continue
					}
					items, ok := u.Body.Projects[pname]
					if !ok {
						items = map[model.Name]*model.Item{}
						u.Body.Projects[pname] = items
						created++
					}
					keys := make([]string, 0, len(groups[g]))
					for k := range groups[g] {
						keys = append(keys, k)
					}
					slices.Sort(keys)
					for _, k := range keys {
						sec := groups[g][k]
						iname, err := model.ParseName(k)
						if err != nil {
							fmt.Fprintf(stderr, "lockr: warning: skipping %s/%q: %v\n", pname, k, err)
							skipped++
							continue
						}
						if _, exists := items[iname]; exists {
							fmt.Fprintf(stderr, "lockr: warning: %s/%s already exists, not overwriting\n", pname, iname)
							skipped++
							continue
						}
						t := sec.UpdatedAt
						if t.IsZero() {
							t = now().UTC()
						}
						it := &model.Item{Kind: model.KindSecret, Secret: []byte(sec.Value), CreatedAt: t, UpdatedAt: t}
						if e, err := model.ParseEnvName(strings.ToUpper(k)); err == nil {
							it.Env = e
						}
						items[iname] = it
						imported++
					}
				}
				fmt.Fprintf(stdout, "Imported %d items into %d new projects (%d skipped)\n", imported, created, skipped)
				return nil
			})
		},
	}
	c.Flags().StringVar(&prefix, "project-prefix", "", "prefix for imported project names")
	return c
}
