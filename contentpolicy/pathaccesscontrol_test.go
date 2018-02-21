package contentpolicy

import (
	"testing"
)

func TestDomainModifierRespected(t *testing.T) {
	filter := NewPathAccessControl()
	err := filter.AddFilter("*$taboola.com")
	if err != nil {
		t.Error(err)
	}

	filter.Compile()

	bp, err := filter.EvaluateRequest("example.com", "https://images.taboola.com/taboola/image/fetch/f_jpg%2Cq_auto%2Ch_200%2Cw_360%2Cc_fill%2Cg_faces:auto%2Ce_sharpen/http%3A//cdn.taboola.com/libtrc/static/thumbnails/9a93cedf9ee63b8e4e3e36bc48ee930b.jpg", true, ContentTypeImage)
	if err != nil {
		t.Error(err)
	}

	if bp != false {
		t.Errorf("Path should not be blocked")
	}
}

func TestDomainMatchesStartDoublePipe(t *testing.T) {
	filter := NewPathAccessControl()
	err := filter.AddFilter("||example.com/ads")
	if err != nil {
		t.Error(err)
	}

	filter.Compile()

	br, err := filter.EvaluateRequest("site.test.net", "example.com/ads/buythiscoolthing.gif", true, ContentTypeImage)
	if err != nil {
		t.Error(err)
	}

	if br != true {
		t.Errorf("Rule ||example.com/ads should have blocked example.com/ads/buythiscoolthing.gif")
	}

	br, err = filter.EvaluateRequest("site.test.net", "www.example.com/ads/buythiscoolthing.gif", true, ContentTypeImage)
	if err != nil {
		t.Error(err)
	}

	if br != true {
		t.Errorf("Rule ||example.com/ads should have blocked www.example.com/ads/buythiscoolthing.gif")
	}
}

func TestAbsoluteMatchStartSinglePipe(t *testing.T) {
	filter := NewPathAccessControl()
	err := filter.AddFilter("|example.com/ads")
	if err != nil {
		t.Error(err)
	}

	filter.Compile()

	br, err := filter.EvaluateRequest("site.test.net", "example.com/ads/buythiscoolthing.gif", true, ContentTypeImage)
	if err != nil {
		t.Error(err)
	}

	if br != true {
		t.Errorf("Rule |example.com/ads should have blocked example.com/ads/buythiscoolthing.gif")
	}

	br, err = filter.EvaluateRequest("site.test.net", "www.example.com/ads/buythiscoolthing.gif", true, ContentTypeImage)
	if err != nil {
		t.Error(err)
	}

	if br == true {
		t.Errorf("Rule |example.com/ads should not have blocked www.example.com/ads/buythiscoolthing.gif")
	}
}
