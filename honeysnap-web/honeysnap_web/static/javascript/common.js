function toggleVisible(elem) {
    toggleElementClass("invisible", elem);
}    
var roundedCornersOnLoad = function () {
    roundElement("menu", null);  
    roundElement("bottommenu", null);
};
addLoadEvent(roundedCornersOnLoad);