import { LinkPreset, type NavBarLink } from "@/types/config";
import I18nKey from "@i18n/i18nKey";
import { i18n } from "@i18n/translation";

export const LinkPresets: { [key in LinkPreset]: NavBarLink } = {
	[LinkPreset.Home]: {
		name: i18n(I18nKey.home),
		url: "/",
	},
	[LinkPreset.Blogs]: {
		name: i18n(I18nKey.blogs),
		url: "/archive/category/Blogs/",
	},
	[LinkPreset.Writeups]: {
		name: i18n(I18nKey.writeup),
		url: "/archive/category/Writeups/",
	},
	[LinkPreset.About]: {
		name: i18n(I18nKey.about),
		url: "/about/",
	},
};
