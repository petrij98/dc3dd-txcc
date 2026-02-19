/^# Packages using this file: / {
  s/# Packages using this file://
  ta
  :a
  s/ dc3dd / dc3dd /
  tb
  s/ $/ dc3dd /
  :b
  s/^/# Packages using this file:/
}
