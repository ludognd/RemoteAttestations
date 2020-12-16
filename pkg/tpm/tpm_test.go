package tpm_test

//func TestOpen(t *testing.T) {
//	got, err := Open()
//	if err != nil {
//		t.Errorf("Open() returned an error: %s", err)
//	}
//	if got.contextHandle == nil {
//		t.Errorf("Open() returned a nil contextHandle")
//	}
//	if got.tpmHandle == nil {
//		t.Errorf("Open() returned a nil contextHandle")
//	}
//	t.Log("Open: success")
//}
//
//func TestTPM_IsOwned(t *testing.T) {
//	filename := "/sys/class/tpm/tpm0/device/owned"
//	val, err := ioutil.ReadFile(filename)
//	if err != nil {
//		t.Errorf("Unable to read %s: %s", filename, err)
//	}
//	tpm, err := Open()
//	if err != nil {
//		t.Errorf("Open() returned an error: %s", err)
//	}
//	got, err := tpm.IsOwned()
//
//	if (string(val) == "0" && got == true) || (string(val) == "1" && got == false) {
//		t.Errorf("Owned: %s got: %t", val, got)
//	}
//	t.Log("IsOwned: success")
//}
//
////func TestTPM_GetEK(t *testing.T) {
////	tpm, err := Open()
////	if err != nil {
////		t.Errorf("Open() returned an error: ", err)
////	}
////	ek, err := tpm.GetEK()
////}
