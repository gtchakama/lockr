// `lockr list`: item metadata table. Never prints secret values or seeds.
package cmd

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/gtchakama/lockr/internal/model"
	"github.com/spf13/cobra"
)

const rotateAfter = 90 * 24 * time.Hour

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list [project]",
		Short: "List items (metadata only)",
		Args:  usageArgs(cobra.MaximumNArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			var only model.Name
			if len(args) == 1 {
				n, err := model.ParseName(args[0])
				if err != nil {
					return usageWrap(err)
				}
				only = n
			}
			u, _, err := openRead(true)
			if err != nil {
				return err
			}
			defer u.Close()
			projects := sortedNames(u.Body.Projects)
			if only != "" {
				if _, ok := u.Body.Projects[only]; !ok {
					return fmt.Errorf("project %q %w", only, model.ErrNotFound)
				}
				projects = []model.Name{only}
			}
			tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "REF\tKIND\tUSERNAME\tURL\tENV\tUPDATED\t")
			t := now()
			for _, p := range projects {
				items := u.Body.Projects[p]
				for _, n := range sortedNames(items) {
					it := items[n]
					updated := it.UpdatedAt.Local().Format("2006-01-02")
					if t.Sub(it.UpdatedAt) > rotateAfter {
						updated += " ⚠ rotate"
					}
					kind := string(it.Kind)
					if it.TOTPSeed != "" {
						kind += "+totp"
					}
					fmt.Fprintf(tw, "%s/%s\t%s\t%s\t%s\t%s\t%s\t\n", p, n, kind, dash(it.Username), dash(it.URL), dash(string(it.Env)), updated)
				}
			}
			return tw.Flush()
		},
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
