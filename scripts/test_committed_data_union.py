"""Run the standard Patricia union CI regressions. Per-call billing supersedes the custom proof owner and slot fields."""

from test_committed_data_patricia import check_union


if __name__ == "__main__":
    check_union()
