import tempfile
import os
from pathlib import Path
from mira.core.artifact import ArtifactStore, ArtifactError


def test_artifact_store():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        store = ArtifactStore(root, max_file_size=1024)  # 1KB limit for testing

        # Create a test file inside root
        test_file = root / "test.txt"
        test_file.write_text("Hello, world!")

        # Register the file
        artifact = store.register("test1", test_file)
        print(f"Registered artifact: {artifact.artifact_id}")
        print(f"Path: {artifact.path}")
        print(f"File type: {artifact.file_type}")
        print(f"Size: {artifact.size}")
        print(f"SHA256: {artifact.sha256}")

        # Retrieve the artifact
        retrieved = store.get("test1")
        assert retrieved.artifact_id == artifact.artifact_id
        assert retrieved.path == artifact.path
        assert retrieved.size == artifact.size
        assert retrieved.sha256 == artifact.sha256
        print("Retrieval successful")

        # Test duplicate ID
        try:
            store.register("test1", test_file)
            assert False, "Expected ArtifactError for duplicate ID"
        except ArtifactError as e:
            print(f"Duplicate ID correctly raised: {e}")

        # Test non-existent file
        try:
            store.register("test2", root / "nonexistent.txt")
            assert False, "Expected ArtifactError for non-existent file"
        except ArtifactError as e:
            print(f"Non-existent file correctly raised: {e}")

        # Test file outside root
        outside_dir = Path(tmpdir + "_outside")
        outside_dir.mkdir()
        outside_file = outside_dir / "outside.txt"
        outside_file.write_text("outside")
        try:
            store.register("test3", outside_file)
            assert False, "Expected ArtifactError for outside file"
        except ArtifactError as e:
            print(f"Outside file correctly raised: {e}")

        # Test size limit
        big_file = root / "big.txt"
        big_file.write_text("x" * 2000)  # 2000 bytes > 1024 limit
        try:
            store.register("test4", big_file)
            assert False, "Expected ArtifactError for size limit"
        except ArtifactError as e:
            print(f"Size limit correctly raised: {e}")

        # Test file type detection (should be unknown for text file)
        assert artifact.file_type == "unknown"
        print('File type detection returned "unknown" for text file')

        print("All tests passed!")


if __name__ == "__main__":
    test_artifact_store()
