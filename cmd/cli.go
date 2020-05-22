package cmd

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/presenter"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal/config"
	"github.com/spf13/viper"
)

var cliOpts = config.CliOnlyOptions{}

func setCliOptions() {
	rootCmd.PersistentFlags().StringVarP(&cliOpts.ConfigPath, "config", "c", "", "application config file")

	// scan options
	flag := "scope"
	rootCmd.Flags().StringP(
		"scope", "s", scope.AllLayersScope.String(),
		fmt.Sprintf("selection of layers to analyze, options=%v", scope.Options))
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
	}

	// output & formatting options
	flag = "output"
	rootCmd.Flags().StringP(
		flag, "o", presenter.JSONPresenter.String(),
		fmt.Sprintf("report output formatter, options=%v", presenter.Options),
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
	}

	flag = "quiet"
	rootCmd.Flags().BoolP(
		flag, "q", false,
		"suppress all auxiliary output",
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
	}

	rootCmd.Flags().CountVarP(&cliOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
}
