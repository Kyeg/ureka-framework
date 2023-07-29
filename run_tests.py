import pytest

# Also follow pytest.ini for adding parameter
if __name__ == "__main__":
    # For example, stop when any test failed
    # pytest.main(["-x"])

    # For example, qruit or verbose
    # pytest.main(["-q"])
    # pytest.main(["-v"])

    # For example, add stdout/stderr/stdin (can be replaced by pytest-log)
    pytest.main(["-q", "-s"])

    # For example, select test case by selecting marker
    # pytest.main(["-m", "mark_name"])
    # pytest.main(["-m", "not mark_name"])5

    # For example, add histogram from pytest-benchmark
    # pytest.main(["-m", "benchmark", "--benchmark-histogram"])

    # For example, add command line argument
    # pytest.main(["-s", "--arg", "1", "--arg2", "y"])
    # pytest.main(["-s", "--arg", "2", "--arg2", "n"])

    # For example, generate test report from pytest-cover
    # We can further omit some sources in .coveragerc
    # pytest.main(
    #     [
    #         "-x",
    #         "-q",
    #         "-m",
    #         "not benchmark",
    #         "--cov=ureka_framework/",
    #         "--cov-report=html",
    #         "--cov-config=.coveragerc",
    #     ]
    # )
