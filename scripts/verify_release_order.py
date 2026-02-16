from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PackageReleaseSpec:
    name: str
    depends_on: tuple[str, ...] = field(default_factory=tuple)


def verify_release_order(
    release_order: tuple[str, ...], package_specs: tuple[PackageReleaseSpec, ...]
) -> None:
    package_index = {name: index for index, name in enumerate(release_order)}
    for spec in package_specs:
        if spec.name not in package_index:
            raise SystemExit(f"Package '{spec.name}' missing from release order.")
        for dependency in spec.depends_on:
            if dependency not in package_index:
                raise SystemExit(
                    f"Dependency '{dependency}' for package '{spec.name}' missing from release order."
                )
            if package_index[dependency] > package_index[spec.name]:
                raise SystemExit(
                    f"Invalid order: dependency '{dependency}' must be released before '{spec.name}'."
                )


def main() -> None:
    package_specs = (
        PackageReleaseSpec(name="predicate-contracts"),
        PackageReleaseSpec(name="predicate-authority", depends_on=("predicate-contracts",)),
    )
    release_order = ("predicate-contracts", "predicate-authority")
    verify_release_order(release_order=release_order, package_specs=package_specs)
    print("Release order validated: predicate-contracts -> predicate-authority")


if __name__ == "__main__":
    main()
