"""Create fixed-size random binary input files for cryptography experiments."""

from pathlib import Path
import secrets


INPUT_SIZES = {
    "input_1KiB.bin": 1024,
    "input_10KiB.bin": 10240,
    "input_100KiB.bin": 102400,
    "input_1MiB.bin": 1048576,
    "input_10MiB.bin": 10485760,
}


def main() -> None:
    script_directory = Path(__file__).resolve().parent
    inputs_directory = script_directory / "data" / "inputs"
    inputs_directory.mkdir(parents=True, exist_ok=True)

    for filename, expected_size in INPUT_SIZES.items():
        input_path = inputs_directory / filename

        if input_path.exists():
            actual_size = input_path.stat().st_size
            if actual_size != expected_size:
                raise ValueError(
                    f"Existing file {filename} has {actual_size} bytes; "
                    f"expected {expected_size} bytes."
                )
            status = "already existed"
        else:
            input_path.write_bytes(secrets.token_bytes(expected_size))
            actual_size = input_path.stat().st_size
            status = "created"

        print(f"{filename}: {actual_size} bytes ({status})")


if __name__ == "__main__":
    main()
