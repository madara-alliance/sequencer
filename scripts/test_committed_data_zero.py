"""Run the standard Patricia zero CI regressions. Omitted zero leaves replace the custom mismatched-terminal witness."""

from test_committed_data_patricia import check_zero


if __name__ == "__main__":
    check_zero()
