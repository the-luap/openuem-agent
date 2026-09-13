package netbirdjournal

import (
	"testing"

	"github.com/open-uem/nats/enrollment"
)

func TestBootReleaseRequiresIndependentKernelEvidence(t *testing.T) {
	original := Boot{Platform: "windows", Windows: enrollment.SoftwareBootSession{Sequence: 10, SystemProcessCreated: 130000000000000001}}
	for _, next := range []Boot{
		original,
		{Platform: "windows", Windows: enrollment.SoftwareBootSession{Sequence: 11, SystemProcessCreated: original.Windows.SystemProcessCreated}},
		{Platform: "windows", Windows: enrollment.SoftwareBootSession{Sequence: 10, SystemProcessCreated: original.Windows.SystemProcessCreated + 1}},
		{Platform: "windows", Windows: enrollment.SoftwareBootSession{Sequence: 9, SystemProcessCreated: original.Windows.SystemProcessCreated + 1}},
		testBoot(), {},
	} {
		if next.After(original) {
			t.Error("non-boot evidence released an orphan")
		}
	}
	later := Boot{Platform: "windows", Windows: enrollment.SoftwareBootSession{Sequence: 11, SystemProcessCreated: original.Windows.SystemProcessCreated + 1}}
	if !later.After(original) {
		t.Fatal("later kernel boot rejected")
	}
}
