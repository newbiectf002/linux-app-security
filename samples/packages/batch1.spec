Name:           batch1-sample
Version:        1.2.3
Release:        1%{?dist}
Summary:        Safe Step 5 Batch 1 metadata sample
License:        MIT
BuildArch:      x86_64
Requires:       glibc

%description
Metadata-only RPM validation sample containing the reproducible ELF sample.

%install
mkdir -p %{buildroot}/opt/batch1/bin
install -m 0755 %{_sourcedir}/full-hardening %{buildroot}/opt/batch1/bin/batch1

%post
/bin/true

%files
/opt/batch1/bin/batch1
